// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package xlat_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/via64"
	"tailscale.com/net/via64/xlat"
	"tailscale.com/net/via64/xlatbpf"
	"tailscale.com/tstest"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/preftype"
	"tailscale.com/util/clientmetric"
)

// The helpers below repeat netns_linux_test.go's, because this is the external test package.

func addNetNS(t *testing.T, name string) netns.NsHandle {
	t.Helper()
	exec.Command("ip", "netns", "del", name).Run()
	sh(t, "ip netns add "+name)
	t.Cleanup(func() { exec.Command("ip", "netns", "del", name).Run() })
	h, err := netns.GetFromName(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func inNS(ns netns.NsHandle, fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := netns.Set(ns); err != nil {
			errc <- err
			return
		}
		errc <- fn()
	}()
	return <-errc
}

func sh(t *testing.T, cmdline string) string {
	t.Helper()
	f := strings.Fields(cmdline)
	out, err := exec.Command(f[0], f[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", cmdline, err, out)
	}
	return string(out)
}

// listenPMTU listens for UDP on addr with IP_MTU_DISCOVER set to mode.
func listenPMTU(addr string, mode int) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, mode) }); err != nil {
			return err
		}
		return serr
	}}
	return lc.ListenPacket(context.Background(), "udp4", addr)
}

func via(site uint32, v4 string) netip.Addr {
	p, _ := tsaddr.MapVia(site, netip.MustParsePrefix(v4+"/32"))
	return p.Addr()
}

// TestEndToEnd runs a client, a router (whose veth tsx0 stands in for tailscale0) and a LAN host in three namespaces. Two sites, 0x1790 and 7, lead to the same LAN host, and replies must come from the site the client used.
const flowCap = 2500

func TestEndToEnd(t *testing.T) {
	tstest.RequireRoot(t)
	r := addNetNS(t, "via64-r")
	cl := addNetNS(t, "via64-c")
	lan := addNetNS(t, "via64-l")
	for _, cmd := range []string{
		"ip link add tsx0 netns via64-r type veth peer name eth0 netns via64-c",
		"ip link add lan0 netns via64-r type veth peer name eth0 netns via64-l",
		"ip -n via64-r addr add fe80::1/64 dev tsx0 nodad",
		"ip -n via64-r link set tsx0 up",
		"ip -n via64-r -6 route add fd7a:115c:a1e0::2/128 via fe80::2 dev tsx0",
		"ip -n via64-r addr add 10.99.0.1/24 dev lan0",
		"ip -n via64-r link set lan0 up",
		"ip netns exec via64-r sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1",
		"ip -n via64-c addr add fe80::2/64 dev eth0 nodad",
		"ip -n via64-c addr add fd7a:115c:a1e0::2/128 dev eth0 nodad",
		"ip -n via64-c link set eth0 up",
		"ip -n via64-c -6 route add fd7a:115c:a1e0:b1a::/64 via fe80::1 dev eth0",
		"ip -n via64-l addr add 10.99.0.2/24 dev eth0",
		"ip -n via64-l link set eth0 up",
		// Stand-in for Tailscale's own IPv6 subnet-route masquerade, which also sees these packets; via64's NAT66 must win.
		"ip netns exec via64-r nft add table ip6 competing",
		"ip netns exec via64-r nft add chain ip6 competing post { type nat hook postrouting priority 100 ; }",
		"ip netns exec via64-r nft add rule ip6 competing post oifname tsvia0 meta mark and 0xff0000 == 0x40000 masquerade", // linuxfw matches the subnet-route mark
		// Docker's forward drop policy, with linuxfw's accepts in the same chain.
		"ip netns exec via64-r nft add table ip filter",
		"ip netns exec via64-r nft add chain ip filter FORWARD { type filter hook forward priority 0 ; policy drop ; }",
		"ip netns exec via64-r nft add rule ip filter FORWARD iifname tsx0 meta mark set meta mark or 0x40000",
		"ip netns exec via64-r nft add rule ip filter FORWARD meta mark and 0xff0000 == 0x40000 accept",
		"ip netns exec via64-r nft add rule ip filter FORWARD oifname tsx0 accept",
		"ip netns exec via64-r nft add table ip6 filter",
		"ip netns exec via64-r nft add chain ip6 filter FORWARD { type filter hook forward priority 0 ; policy drop ; }",
		"ip netns exec via64-r nft add rule ip6 filter FORWARD iifname tsx0 meta mark set meta mark or 0x40000",
		"ip netns exec via64-r nft add rule ip6 filter FORWARD meta mark and 0xff0000 == 0x40000 accept",
		"ip netns exec via64-r nft add rule ip6 filter FORWARD oifname tsx0 accept",
		// firewalld's and NixOS's IPv6 reverse-path filter.
		"ip netns exec via64-r nft add table inet rpf",
		"ip netns exec via64-r nft add chain inet rpf pre { type filter hook prerouting priority 10 ; }",
		"ip netns exec via64-r nft add rule inet rpf pre meta nfproto ipv6 fib saddr . mark . iif oif missing drop",
		// Stand-in for Tailscale's table 52, which routes all of fd7a:115c:a1e0::/48 to tailscale0.
		"ip -n via64-r -6 route add fd7a:115c:a1e0::/48 dev tsx0",
		// tailscale0's MTU.
		"ip -n via64-r link set tsx0 mtu 1280",
		"ip -n via64-c link set eth0 mtu 1280",
		// A LAN host that filters ICMP "fragmentation needed", as many do, so TCP must not depend on path MTU discovery.
		"ip netns exec via64-l nft add table ip hostfw",
		"ip netns exec via64-l nft add chain ip hostfw input { type filter hook input priority 0 ; }",
		"ip netns exec via64-l nft add rule ip hostfw input icmp type destination-unreachable icmp code frag-needed drop",
	} {
		sh(t, cmd)
	}

	ctlCfg := xlat.Config{
		Ingress:      "tsx0",
		RulePriority: 5190,
		Table:        5264,
		X4:           netip.MustParseAddr("192.0.0.6"),
		NewBackend:   xlatbpf.New,
		Logf:         t.Logf,
		// Above many-connections' 2000, low enough for flow-cap to reach quickly.
		FlowsPerClient: flowCap,
	}
	ctl := xlat.NewController(ctlCfg)
	var udpInKernel bool // false on kernels without conntrack timeout policies
	needUDP := func(t *testing.T) {
		if !udpInKernel {
			t.Skip("UDP stays on netstack, which this test does not run")
		}
	}
	needConntrackTool := func(t *testing.T) {
		if _, err := exec.LookPath("conntrack"); err != nil {
			t.Skip("reads conntrack entries with the conntrack tool (conntrack-tools), which is not installed")
		}
	}
	desired := xlat.Desired{Netfilter: preftype.NetfilterOn, SNAT: true, TunIPv6: true, Advertised: []netip.Prefix{
		netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:1790::/96"),
		netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:7::/96"),
	}}
	update := func(d xlat.Desired) (got []netip.Prefix, err error) {
		inNS(r, func() error { got, err = ctl.Update(d); return nil })
		return got, err
	}
	reassert := func() { inNS(r, func() error { ctl.Reassert(); return nil }) }
	handled, err := update(desired)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			inNS(r, ctl.Close)
		}
	})
	siteA, siteB := via(0x1790, "10.99.0.2"), via(7, "10.99.0.2")
	udpInKernel = via64.KernelHandles(siteA, ipproto.UDP)
	if len(handled) != 2 || !via64.KernelHandles(siteA, ipproto.TCP) || !via64.KernelHandles(siteB, ipproto.TCP) {
		t.Fatalf("Update handled %v", handled)
	}

	var tcpLn, bulkLn, holdLn net.Listener
	var udpConn, lateConn, sinkConn, dfConn, noDFConn net.PacketConn
	if err := inNS(lan, func() (err error) {
		if sinkConn, err = net.ListenPacket("udp4", "10.99.0.2:7004"); err != nil { // for canonical-direct-refused
			return err
		}
		if lateConn, err = net.ListenPacket("udp4", "10.99.0.2:7003"); err != nil { // for udp-idle-45s
			return err
		}
		if tcpLn, err = net.Listen("tcp4", "10.99.0.2:7000"); err != nil {
			return err
		}
		if bulkLn, err = net.Listen("tcp4", "10.99.0.2:7002"); err != nil { // for many-connections; does not report peers
			return err
		}
		// For tcp-half-closed; never reads or closes. Without keepalives, as its probes, answered by the client's orphaned socket, would cross the pair during canonical-direct-refused.
		if holdLn, err = (&net.ListenConfig{KeepAlive: -1}).Listen(context.Background(), "tcp4", "10.99.0.2:7006"); err != nil {
			return err
		}
		// For udp-df-reply: answer a request naming a size with a datagram of that size, with DF always set (as QUIC servers send) or never.
		if dfConn, err = listenPMTU("10.99.0.2:7007", unix.IP_PMTUDISC_DO); err != nil {
			return err
		}
		if noDFConn, err = listenPMTU("10.99.0.2:7008", unix.IP_PMTUDISC_DONT); err != nil {
			return err
		}
		udpConn, err = net.ListenPacket("udp4", "10.99.0.2:7001")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		tcpLn.Close()
		bulkLn.Close()
		holdLn.Close()
		udpConn.Close()
		lateConn.Close()
		sinkConn.Close()
		dfConn.Close()
		noDFConn.Close()
	})
	sunk := make(chan string, 8)
	go func() {
		buf := make([]byte, 64)
		for {
			n, _, err := sinkConn.ReadFrom(buf)
			if err != nil {
				return
			}
			sunk <- string(buf[:n])
		}
	}()
	go func() {
		// Answer at once, then again 45 seconds later: past conntrack's default but within netstack's 2 minutes.
		buf := make([]byte, 64)
		for {
			n, a, err := lateConn.ReadFrom(buf)
			if err != nil {
				return
			}
			msg := string(buf[:n])
			lateConn.WriteTo([]byte("now:"+msg), a)
			time.AfterFunc(45*time.Second, func() { lateConn.WriteTo([]byte("late:"+msg), a) })
		}
	}()
	peers := make(chan string, 8)
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			peers <- c.RemoteAddr().String()
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	var heldMu sync.Mutex
	var held []net.Conn
	t.Cleanup(func() {
		heldMu.Lock()
		defer heldMu.Unlock()
		for _, c := range held {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := holdLn.Accept()
			if err != nil {
				return
			}
			heldMu.Lock()
			held = append(held, c)
			heldMu.Unlock()
		}
	}()
	go func() {
		for {
			c, err := bulkLn.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	for _, pc := range []net.PacketConn{dfConn, noDFConn} {
		go func() {
			buf := make([]byte, 64)
			for {
				n, a, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				size, err := strconv.Atoi(string(buf[:n]))
				if err != nil || size > 65507 {
					continue
				}
				pc.WriteTo(bytes.Repeat([]byte{'q'}, size), a)
			}
		}()
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, a, err := udpConn.ReadFrom(buf)
			if err != nil {
				return
			}
			udpConn.WriteTo(buf[:n], a)
		}
	}()

	dial := func(d *net.Dialer, dst netip.Addr, port uint16) (net.Conn, error) {
		var c net.Conn
		err := inNS(cl, func() (err error) {
			c, err = d.Dial("tcp6", netip.AddrPortFrom(dst, port).String())
			return err
		})
		return c, err
	}
	echo := func(t *testing.T, c net.Conn) {
		t.Helper()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(c, "hello")
		buf := make([]byte, 5)
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
			t.Fatalf("echo = %q, %v", buf, err)
		}
		if got := <-peers; !strings.HasPrefix(got, "10.99.0.1:") {
			t.Errorf("LAN host saw %s; want the router's LAN address (NAT44)", got)
		}
	}
	echoTCP := func(t *testing.T, dst netip.Addr) {
		t.Helper()
		c, err := dial(&net.Dialer{Timeout: 5 * time.Second}, dst, 7000)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		echo(t, c)
	}

	t.Run("tcp-site-1790", func(t *testing.T) { echoTCP(t, siteA) })
	t.Run("ruleset-matches-udp-mode", func(t *testing.T) {
		out := sh(t, "ip netns exec via64-r nft list table ip6 ts-via64")
		if udpInKernel == strings.Contains(out, "meta l4proto != udp") || udpInKernel != strings.Contains(out, "via64-udp") {
			t.Errorf("ruleset does not match UDP in the kernel = %v:\n%s", udpInKernel, out)
		}
	})
	t.Run("tcp-site-7", func(t *testing.T) { echoTCP(t, siteB) })

	t.Run("same-port-two-sites", func(t *testing.T) {
		// After the canonical DNAT both connections have the same tuple; conntrack's NAT must give the second a different source port.
		reuse := func(network, address string, rc syscall.RawConn) error {
			var serr error
			rc.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1) })
			return serr
		}
		local := &net.TCPAddr{IP: net.ParseIP("fd7a:115c:a1e0::2"), Port: 45000}
		d := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: local, Control: reuse}
		a, err := dial(d, siteA, 7000)
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		b, err := dial(d, siteB, 7000)
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()
		echo(t, a)
		echo(t, b)
	})

	t.Run("tcp-refused", func(t *testing.T) {
		c, err := dial(&net.Dialer{Timeout: 5 * time.Second}, siteA, 7999)
		if err == nil {
			c.Close()
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			t.Errorf("dial to a closed port: %v; want ECONNREFUSED from the LAN host, end to end", err)
		}
	})

	t.Run("tcp-host-down", func(t *testing.T) {
		// The router's "host unreachable" must reach the client, so it fails fast as through netstack.
		start := time.Now()
		c, err := dial(&net.Dialer{Timeout: 15 * time.Second}, via(0x1790, "10.99.0.99"), 7000)
		if err == nil {
			c.Close()
		}
		if took := time.Since(start); !(errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH)) || took > 8*time.Second {
			t.Errorf("dial to a LAN host that is down: %v after %v; want unreachable within a few seconds", err, took.Round(time.Millisecond))
		}
	})

	t.Run("udp-port-unreachable", func(t *testing.T) {
		needUDP(t)
		var c net.Conn
		if err := inNS(cl, func() (err error) { c, err = net.Dial("udp6", netip.AddrPortFrom(siteA, 7998).String()); return err }); err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write([]byte("anyone?"))
		if _, err := c.Read(make([]byte, 16)); !errors.Is(err, syscall.ECONNREFUSED) {
			t.Errorf("read after sending to a closed UDP port: %v; want ECONNREFUSED", err)
		}
	})

	t.Run("udp", func(t *testing.T) {
		needUDP(t)
		var c net.Conn
		if err := inNS(cl, func() (err error) { c, err = net.Dial("udp6", netip.AddrPortFrom(siteB, 7001).String()); return err }); err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		c.Write([]byte("hi"))
		buf := make([]byte, 16)
		if n, err := c.Read(buf); err != nil || string(buf[:n]) != "hi" {
			t.Fatalf("echo = %q, %v", buf[:n], err)
		}
	})

	t.Run("udp-fragmented", func(t *testing.T) {
		needUDP(t)
		// A datagram larger than tailscale0's MTU travels as fragments both ways, as it does through netstack.
		var c net.Conn
		if err := inNS(cl, func() (err error) { c, err = net.Dial("udp6", netip.AddrPortFrom(siteA, 7001).String()); return err }); err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		msg := bytes.Repeat([]byte("0123456789"), 300)
		if _, err := c.Write(msg); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		if n, err := c.Read(buf); err != nil || !bytes.Equal(buf[:n], msg) {
			t.Fatalf("echo of a %d-byte datagram: %d bytes, %v", len(msg), n, err)
		}
	})

	t.Run("udp-df-reply", func(t *testing.T) {
		needUDP(t)
		// A 1232-byte DNS-sized answer with DF set is 1260 bytes as IPv4, which the peer's MTU passes whole, to a LAN host that ignores "fragmentation needed".
		for _, size := range []int{1224, 1232} {
			var c net.Conn
			if err := inNS(cl, func() (err error) { c, err = net.Dial("udp6", netip.AddrPortFrom(siteA, 7001).String()); return err }); err != nil {
				t.Fatal(err)
			}
			c.SetDeadline(time.Now().Add(3 * time.Second))
			msg := bytes.Repeat([]byte{'d'}, size)
			c.Write(msg)
			buf := make([]byte, 2048)
			if n, err := c.Read(buf); err != nil || n != size {
				t.Errorf("echo of a %d-byte datagram: %d bytes, %v", size, n, err)
			}
			c.Close()
		}
		/*
			Replies over 1260 bytes as IPv4, with DF (QUIC servers set it and send datagrams of about 1350 bytes, and this LAN host ignores "fragmentation needed") and without. Without DF they reach the client whole, as fragments, as they do through netstack. With DF the default follows RFC 7915 4.1: the router drops them and sends "fragmentation needed". With SplitUDP the translator delivers them as fragments too.

			A router counter checks that each reply arrived from the LAN as sent, so the test cannot pass by the server falling back to fragmenting itself.
		*/
		sizes := []int{1300, 1350, 1400, 1472}
		const burst = 3 // datagrams of each size, back to back, so their fragments interleave in the client's reassembly as QUIC's would
		bigReplies := func(t *testing.T, split bool) {
			sh(t, "ip netns exec via64-r nft add table ip bigudp")
			defer sh(t, "ip netns exec via64-r nft delete table ip bigudp")
			sh(t, "ip netns exec via64-r nft add chain ip bigudp pre { type filter hook prerouting priority -300 ; }")
			sh(t, "ip netns exec via64-r nft add rule ip bigudp pre iifname lan0 udp sport 7007 ip frag-off 0x4000 ip length > 1260 counter")
			sh(t, "ip netns exec via64-r nft add rule ip bigudp pre iifname lan0 udp sport 7008 ip frag-off 0 ip length > 1260 counter")
			sh(t, "ip netns exec via64-r nft add chain ip bigudp out { type filter hook output priority 0 ; }")
			sh(t, "ip netns exec via64-r nft add rule ip bigudp out oifname lan0 icmp type destination-unreachable icmp code frag-needed counter")
			// Every "fragmentation needed" is counted, not just the first few per second.
			old := strings.TrimSpace(sh(t, "ip netns exec via64-r sysctl -n net.ipv4.icmp_ratelimit"))
			sh(t, "ip netns exec via64-r sysctl -qw net.ipv4.icmp_ratelimit=0")
			defer sh(t, "ip netns exec via64-r sysctl -qw net.ipv4.icmp_ratelimit="+old)
			for _, port := range []uint16{7007, 7008} {
				deliver := port == 7008 || split
				var c *net.UDPConn
				if err := inNS(cl, func() (err error) {
					c, err = net.DialUDP("udp6", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(siteA, port)))
					return err
				}); err != nil {
					t.Fatal(err)
				}
				for _, size := range sizes {
					for range burst {
						c.Write([]byte(strconv.Itoa(size)))
					}
					buf := make([]byte, 2048)
					if !deliver {
						c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
						if n, err := c.Read(buf); err == nil {
							t.Errorf("port %d: got a %d-byte reply to a request for %d bytes with DF; want it dropped", port, n, size)
						}
						continue
					}
					c.SetReadDeadline(time.Now().Add(3 * time.Second))
					for i := range burst {
						n, err := c.Read(buf)
						if err != nil || n != size || !bytes.Equal(buf[:n], bytes.Repeat([]byte{'q'}, size)) {
							t.Errorf("port %d: reply %d of %d bytes: got %d bytes, %v", port, i, size, n, err)
							break
						}
					}
				}
				c.Close()
			}
			out := sh(t, "ip netns exec via64-r nft list table ip bigudp")
			want := 2 // DF and no DF replies from the LAN
			if !split {
				want = 3 // and as many "fragmentation needed" as DF replies
			}
			if got := strings.Count(out, "counter packets "+strconv.Itoa(burst*len(sizes))+" "); got != want {
				t.Errorf("want %d counters at %d:\n%s", want, burst*len(sizes), out)
			}
			if split && !strings.Contains(out, "icmp code 4 counter packets 0 ") {
				t.Errorf("SplitUDP still sent fragmentation needed:\n%s", out)
			}
		}
		t.Run("default", func(t *testing.T) { bigReplies(t, false) })
		t.Run("split", func(t *testing.T) {
			// Rebuild the datapath with SplitUDP, and put the default back for the subtests after this one.
			on := ctlCfg
			on.SplitUDP = true
			swap := func(cfg xlat.Config) {
				if err := inNS(r, ctl.Close); err != nil {
					t.Fatalf("Close: %v", err)
				}
				ctl = xlat.NewController(cfg)
				if _, err := update(desired); err != nil {
					t.Fatalf("Update: %v", err)
				}
			}
			swap(on)
			defer swap(ctlCfg)
			if rules := sh(t, "ip -n via64-r rule"); !strings.Contains(rules, "fwmark 0x2000000/0x2000000 lookup 5266") {
				t.Errorf("no rule to the split route:\n%s", rules)
			}
			metric := func() int64 {
				reassert()
				for _, m := range clientmetric.Metrics() {
					if m.Name() == "via64_xlat_4to6_split" {
						return m.Value()
					}
				}
				return 0
			}
			before := metric()
			// Across the veth the replies arrive CHECKSUM_PARTIAL, as from a local container. With the LAN host's checksum offload off they arrive with the whole checksum, as from a NIC, which the split must keep right.
			bigReplies(t, true)
			sh(t, "ip netns exec via64-l ethtool -K eth0 tx off")
			defer sh(t, "ip netns exec via64-l ethtool -K eth0 tx on")
			bigReplies(t, true)
			if got := metric() - before; got != int64(2*burst*len(sizes)) {
				t.Errorf("via64_xlat_4to6_split grew by %d; want %d", got, 2*burst*len(sizes))
			}
		})
		// TCP is untouched: full-size segments still pass both ways, by the MSS clamp, after the UDP above.
		c, err := dial(&net.Dialer{Timeout: 5 * time.Second}, siteA, 7002)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		msg := bytes.Repeat([]byte("abcdefghijklmnop"), 1<<16)
		go c.Write(msg)
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("TCP echo of %d bytes after the UDP: %v", len(msg), err)
		}
	})

	t.Run("tcp-upload-without-df", func(t *testing.T) {
		// RFC 7915 5.1: translated packets of 1260 bytes or less have DF clear, including each segment of a GSO batch.
		sh(t, "ip netns exec via64-l nft add table ip dfchk")
		sh(t, "ip netns exec via64-l nft add chain ip dfchk in { type filter hook input priority 0 ; }")
		sh(t, "ip netns exec via64-l nft add rule ip dfchk in tcp dport 7002 ip frag-off & 0x4000 != 0 counter")
		sh(t, "ip netns exec via64-l nft add rule ip dfchk in tcp dport 7002 counter")
		defer sh(t, "ip netns exec via64-l nft delete table ip dfchk")
		c, err := dial(&net.Dialer{Timeout: 5 * time.Second}, siteA, 7002)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		msg := bytes.Repeat([]byte("u"), 1<<20)
		go c.Write(msg)
		if _, err := io.ReadFull(c, make([]byte, len(msg))); err != nil {
			t.Fatal(err)
		}
		out := sh(t, "ip netns exec via64-l nft list table ip dfchk")
		var counts []int
		for _, f := range strings.Split(out, "packets ")[1:] {
			n, _ := strconv.Atoi(strings.Fields(f)[0])
			counts = append(counts, n)
		}
		if len(counts) != 2 || counts[1] < 10 || counts[0] != 0 {
			t.Errorf("segments with DF / all segments = %v; want none with DF:\n%s", counts, out)
		}
	})

	t.Run("tcp-half-closed", func(t *testing.T) {
		// Established flows get the kernel's timeout capped at xlat's 4 hours; half-closed ones keep the kernel's own short timeouts, so orphaned flows do not hold conntrack entries for days.
		if !strings.Contains(sh(t, "ip netns exec via64-r nft list table ip6 ts-via64"), "via64-tcp") {
			t.Skip("no TCP timeout policy installed (the kernel lacks conntrack timeout policies); flows get its defaults")
		}
		needConntrackTool(t)
		c, err := dial(&net.Dialer{Timeout: 5 * time.Second}, siteA, 7006)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		sysctl := func(name string) int {
			n, _ := strconv.Atoi(strings.TrimSpace(sh(t, "ip netns exec via64-r cat /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_"+name)))
			return n
		}
		want := map[string]int{
			"ESTABLISHED": min(sysctl("established"), 4*60*60),
			"FIN_WAIT":    sysctl("fin_wait"),
			"CLOSE_WAIT":  sysctl("close_wait"),
		}
		// check waits for the entry in each family to reach one of states, then checks its timeout.
		check := func(when string, states ...string) {
			t.Helper()
			for _, fam := range []string{"ipv6", "ipv4"} {
				var f []string
				for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
					out, _ := exec.Command("ip", "netns", "exec", "via64-r", "conntrack", "-L", "-f", fam, "-p", "tcp", "--orig-port-dst", "7006").Output()
					if f = strings.Fields(string(out)); len(f) >= 4 && slices.Contains(states, f[3]) {
						break
					}
				}
				if len(f) < 4 || !slices.Contains(states, f[3]) {
					t.Fatalf("%s: no %s conntrack entry in %v: %q", when, fam, states, f)
				}
				// The policy's timeout, not google/nftables' 12-hour default or the kernel's 5 days.
				if n, _ := strconv.Atoi(f[2]); n < want[f[3]]-60 || n > want[f[3]] {
					t.Errorf("%s: %s entry in %s expires in %d s; want %d s", when, fam, f[3], n, want[f[3]])
				}
			}
		}
		check("open", "ESTABLISHED")
		c.(*net.TCPConn).CloseWrite()
		// Not FIN_WAIT: while the FIN is unacknowledged, conntrack applies its unacknowledged timeout instead.
		check("half-closed", "CLOSE_WAIT")
	})

	t.Run("tcp-bulk", func(t *testing.T) {
		// Full-size segments both ways, with a LAN host that ignores "fragmentation needed".
		c, err := dial(&net.Dialer{Timeout: 5 * time.Second}, siteA, 7002)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		msg := bytes.Repeat([]byte("abcdefghijklmnop"), 1<<16)
		go c.Write(msg)
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("echo of %d bytes: %v", len(msg), err)
		}
	})

	t.Run("route-change-keeps-udp-timeouts", func(t *testing.T) {
		needUDP(t)
		needConntrackTool(t)
		// Advertising another site rewrites the NAT rules; flows already open must keep netstack's 2-minute UDP timeout.
		var c *net.UDPConn
		if err := inNS(cl, func() (err error) {
			c, err = net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("fd7a:115c:a1e0::2"), Port: 45003})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		c.WriteToUDPAddrPort([]byte("hi"), netip.AddrPortFrom(siteA, 7001))
		buf := make([]byte, 16)
		if _, err := c.Read(buf); err != nil {
			t.Fatal(err)
		}
		timeout := func() int {
			out, _ := exec.Command("ip", "netns", "exec", "via64-r", "conntrack", "-L", "-f", "ipv6", "-p", "udp", "--orig-port-src", "45003").Output() // stdout only; the summary goes to stderr
			f := strings.Fields(string(out))
			if len(f) < 3 {
				t.Fatalf("no conntrack entry for the flow: %q", out)
			}
			n, _ := strconv.Atoi(f[2])
			return n
		}
		if got := timeout(); got < 100 {
			t.Fatalf("timeout before the route change = %d; want about 120", got)
		}
		more := desired
		more.Advertised = append(slices.Clone(desired.Advertised), netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:9::/96"))
		if _, err := update(more); err != nil {
			t.Fatal(err)
		}
		defer update(desired)
		// The kernel applies a flow's timeout when a packet refreshes it, so exchange one more.
		c.WriteToUDPAddrPort([]byte("hi"), netip.AddrPortFrom(siteA, 7001))
		if _, err := c.Read(buf); err != nil {
			t.Fatal(err)
		}
		if got := timeout(); got < 100 {
			t.Errorf("timeout after another site was advertised = %d; want about 120 (the flow lost its timeout policy)", got)
		}
	})

	t.Run("udp-gso", func(t *testing.T) {
		needUDP(t)
		// One UDP_SEGMENT send is a single GSO skb; it must be segmented before the translator.
		var c *net.UDPConn
		if err := inNS(cl, func() error {
			uc, err := net.DialUDP("udp6", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(siteA, 7001)))
			if err != nil {
				return err
			}
			rc, err := uc.SyscallConn()
			if err != nil {
				return err
			}
			var serr error
			if err := rc.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), unix.SOL_UDP, unix.UDP_SEGMENT, 1000) }); err != nil {
				return err
			}
			c = uc
			return serr
		}); err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(bytes.Repeat([]byte("x"), 3000)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		for i := range 3 {
			n, err := c.Read(buf)
			if err != nil || n != 1000 {
				t.Fatalf("reply %d: %d bytes, %v; want 1000", i, n, err)
			}
		}
	})

	t.Run("same-port-two-sites-udp", func(t *testing.T) {
		needUDP(t)
		// Two UDP flows from one client port to the same LAN host through two sites stay separate, each answered from the site it used.
		var c *net.UDPConn
		if err := inNS(cl, func() (err error) {
			c, err = net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("fd7a:115c:a1e0::2"), Port: 45001})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		for _, dst := range []netip.Addr{siteA, siteB} {
			if _, err := c.WriteToUDPAddrPort([]byte(dst.String()), netip.AddrPortFrom(dst, 7001)); err != nil {
				t.Fatal(err)
			}
		}
		got := map[netip.Addr]string{}
		buf := make([]byte, 128)
		for range 2 {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				t.Fatal(err)
			}
			got[from.Addr()] = string(buf[:n])
		}
		for _, dst := range []netip.Addr{siteA, siteB} {
			if got[dst] != dst.String() {
				t.Errorf("reply from %v = %q; want %q (replies must come from the site the client used)", dst, got[dst], dst.String())
			}
		}
	})

	t.Run("udp-idle-45s", func(t *testing.T) {
		needUDP(t)
		if testing.Short() {
			t.Skip("waits 45 seconds")
		}
		var c net.Conn
		if err := inNS(cl, func() (err error) { c, err = net.Dial("udp6", netip.AddrPortFrom(siteA, 7003).String()); return err }); err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte("x"))
		buf := make([]byte, 64)
		for _, want := range []string{"now:x", "late:x"} {
			c.SetDeadline(time.Now().Add(60 * time.Second))
			n, err := c.Read(buf)
			if err != nil || string(buf[:n]) != want {
				t.Fatalf("read %q, %v; want %q (an idle UDP flow must last as long as it does through netstack)", buf[:n], err, want)
			}
		}
	})

	t.Run("ping-two-sites-at-once", func(t *testing.T) {
		errc := make(chan error, 2)
		for _, dst := range []netip.Addr{siteA, siteB} {
			go func() {
				errc <- exec.Command("ip", "netns", "exec", "via64-c", "ping", "-6", "-c3", "-i0.2", "-W2", dst.String()).Run()
			}()
		}
		for range 2 {
			if err := <-errc; err != nil {
				t.Error(err)
			}
		}
	})

	t.Run("ping-full-size", func(t *testing.T) {
		// A full-size echo reply, 1260 bytes as IPv4 without DF, must not be fragmented: fragmented ICMP cannot be translated.
		for _, size := range []string{"1225", "1232"} {
			if out, err := exec.Command("ip", "netns", "exec", "via64-c", "ping", "-6", "-c2", "-i0.2", "-W2", "-s", size, siteA.String()).CombinedOutput(); err != nil {
				t.Errorf("ping -s %s: %v\n%s", size, err, out)
			}
		}
	})

	t.Run("many-connections", func(t *testing.T) {
		// Thousands of flows open at once, split across both sites, all through the one X4.
		const n = 2000
		conns := make([]net.Conn, 0, n)
		defer func() {
			for _, c := range conns {
				c.Close()
			}
		}()
		for i := range n {
			dst := siteA
			if i%2 == 1 {
				dst = siteB
			}
			c, err := dial(&net.Dialer{Timeout: 5 * time.Second}, dst, 7002)
			if err != nil {
				t.Fatalf("connection %d of %d: %v", i, n, err)
			}
			conns = append(conns, c)
		}
		for i, c := range conns {
			c.SetDeadline(time.Now().Add(10 * time.Second))
			msg := fmt.Sprintf("%06d", i)
			io.WriteString(c, msg)
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
				t.Fatalf("connection %d: echo %q, %v", i, buf, err)
			}
		}
		// Each flow is one IPv6 conntrack entry (canonical DNAT and NAT66 together) and one IPv4 entry (NAT44).
		count, _ := strconv.Atoi(strings.TrimSpace(sh(t, "ip netns exec via64-r cat /proc/sys/net/netfilter/nf_conntrack_count")))
		if count < 2*n {
			t.Errorf("nf_conntrack_count = %d; want at least %d", count, 2*n)
		}
	})

	t.Run("canonical-direct-refused", func(t *testing.T) {
		// A peer addressing the canonical prefix directly must not be translated: the guard drops it before it reaches the pair. Watch the LAN side too, since a firewall might drop only the reply.
		txBefore := sh(t, "ip netns exec via64-r cat /sys/class/net/"+xlat.PrimaryName+"/statistics/tx_packets")
		var c net.Conn
		if err := inNS(cl, func() (err error) {
			c, err = net.Dial("udp6", "[fd7a:115c:a1e0:b1a:ff:ffff:a63:2]:7004")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte("direct"))
		select {
		case got := <-sunk:
			t.Fatalf("LAN host received %q sent to the canonical prefix directly", got)
		case <-time.After(2 * time.Second):
		}
		if txAfter := sh(t, "ip netns exec via64-r cat /sys/class/net/"+xlat.PrimaryName+"/statistics/tx_packets"); txAfter != txBefore {
			t.Errorf("%s sent packets (%s to %s) while only canonical-prefix traffic was offered", xlat.PrimaryName, strings.TrimSpace(txBefore), strings.TrimSpace(txAfter))
		}
	})

	// openRaw opens a raw TCP socket in the client's namespace, to send segments its TCP stack never would. It also receives a copy of every TCP segment the client gets.
	openRaw := func(t *testing.T) int {
		t.Helper()
		var fd int
		if err := inNS(cl, func() (err error) {
			if fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_TCP); err != nil {
				return err
			}
			if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_CHECKSUM, 16); err != nil {
				return err
			}
			tv := unix.NsecToTimeval((100 * time.Millisecond).Nanoseconds())
			return unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { unix.Close(fd) })
		return fd
	}
	const (
		tcpFIN = 0x01
		tcpSYN = 0x02
		tcpRST = 0x04
		tcpACK = 0x10
	)
	sendSeg := func(t *testing.T, fd int, dst netip.Addr, sport, dport uint16, seq, ack uint32, flags byte) {
		t.Helper()
		h := make([]byte, 20)
		binary.BigEndian.PutUint16(h[0:], sport)
		binary.BigEndian.PutUint16(h[2:], dport)
		binary.BigEndian.PutUint32(h[4:], seq)
		binary.BigEndian.PutUint32(h[8:], ack)
		h[12] = 5 << 4 // data offset
		h[13] = flags
		binary.BigEndian.PutUint16(h[14:], 65535) // window
		if err := unix.Sendto(fd, h, 0, &unix.SockaddrInet6{Addr: dst.As16()}); err != nil {
			t.Fatalf("sending a segment to %v: %v", dst, err)
		}
	}
	// rstsFrom counts the RSTs from src that the raw socket receives within d.
	rstsFrom := func(fd int, src netip.Addr, d time.Duration) int {
		n := 0
		buf := make([]byte, 1500)
		for deadline := time.Now().Add(d); time.Now().Before(deadline); {
			m, from, err := unix.Recvfrom(fd, buf, 0)
			if err != nil || m < 20 {
				continue
			}
			if sa, ok := from.(*unix.SockaddrInet6); ok && netip.AddrFrom16(sa.Addr) == src && buf[13]&tcpRST != 0 {
				n++
			}
		}
		return n
	}

	t.Run("invalid-not-looped", func(t *testing.T) {
		// Segments conntrack calls invalid skip the DNAT. They must be dropped, not routed back out the tun device, where netstack's 4via6 intercept would answer with a RST, and a live flow must survive them.
		sh(t, "ip netns exec via64-r nft add table ip6 loopchk")
		defer sh(t, "ip netns exec via64-r nft delete table ip6 loopchk")
		sh(t, "ip netns exec via64-r nft add chain ip6 loopchk post { type filter hook postrouting priority 0 ; }")
		sh(t, "ip netns exec via64-r nft add rule ip6 loopchk post oifname tsx0 ip6 daddr fd7a:115c:a1e0:b1a::/64 counter")
		fd := openRaw(t)
		c, err := dial(&net.Dialer{Timeout: 5 * time.Second}, siteA, 7002)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		sport := uint16(c.LocalAddr().(*net.TCPAddr).Port)
		sendSeg(t, fd, siteA, 52000, 7002, 1, 1, tcpSYN|tcpACK)                          // a SYN-ACK with no flow
		sendSeg(t, fd, siteA, sport, 7002, 0x80000000, 0x80000000, tcpACK)               // the live flow, far outside its window
		sendSeg(t, fd, siteA, sport, 7002, 0x80000000, 0x80000000, tcpACK|tcpFIN|tcpSYN) // a bad flag combination
		if n := rstsFrom(fd, siteA, time.Second); n != 0 {
			t.Errorf("client received %d RSTs from %v", n, siteA)
		}
		if out := sh(t, "ip netns exec via64-r nft list table ip6 loopchk"); !strings.Contains(out, "packets 0 ") {
			t.Errorf("untranslated packets left on the tun device:\n%s", out)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(c, "survived")
		buf := make([]byte, 8)
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "survived" {
			t.Errorf("live flow after invalid segments: echo = %q, %v", buf, err)
		}
	})

	t.Run("ack-without-flow-dropped", func(t *testing.T) {
		// tailscaled's filter accepts TCP without SYN whatever the grants, so a segment without SYN must not open a via64 flow: no reply, no LAN traffic and no conntrack entry.
		sh(t, "ip netns exec via64-l nft add table ip ackchk")
		defer sh(t, "ip netns exec via64-l nft delete table ip ackchk")
		sh(t, "ip netns exec via64-l nft add chain ip ackchk input { type filter hook input priority 0 ; }")
		sh(t, "ip netns exec via64-l nft add rule ip ackchk input tcp sport 53000-53009 tcp flags & syn == 0 counter")
		fd := openRaw(t)
		for i, port := range []uint16{7998, 7000} { // closed, and open with no such connection
			sendSeg(t, fd, siteA, 53000+uint16(i), port, 1000, 1000, tcpACK)
			sendSeg(t, fd, siteB, 53002+uint16(i), port, 1000, 1000, tcpACK|tcpFIN)
			sendSeg(t, fd, siteA, 53004+uint16(i), port, 1000, 1000, tcpRST)
		}
		if n := rstsFrom(fd, siteA, time.Second) + rstsFrom(fd, siteB, 100*time.Millisecond); n != 0 {
			t.Errorf("client received %d RSTs for segments without SYN", n)
		}
		if out := sh(t, "ip netns exec via64-l nft list table ip ackchk"); !strings.Contains(out, "packets 0 ") {
			t.Errorf("LAN host received segments without SYN:\n%s", out)
		}
		if _, err := exec.LookPath("conntrack"); err == nil {
			for _, fam := range []string{"ipv6", "ipv4"} {
				out, _ := exec.Command("ip", "netns", "exec", "via64-r", "conntrack", "-L", "-f", fam, "-p", "tcp", "--orig-port-dst", "7998").Output()
				if len(bytes.TrimSpace(out)) != 0 {
					t.Errorf("%s conntrack entries for segments without SYN:\n%s", fam, out)
				}
			}
		}
		// A SYN to the closed port still gets the LAN host's RST, which shows the raw socket sees replies.
		sendSeg(t, fd, siteA, 53009, 7998, 1000, 0, tcpSYN)
		if n := rstsFrom(fd, siteA, 2*time.Second); n != 1 {
			t.Errorf("SYN to a closed port: client received %d RSTs; want 1", n)
		}
	})

	t.Run("flow-cap", func(t *testing.T) {
		// One client's concurrent flows are capped, so it cannot fill the conntrack table for the whole router.
		if out := sh(t, "ip netns exec via64-r nft list table ip6 ts-via64"); !strings.Contains(out, fmt.Sprintf("ct count over %d", flowCap)) {
			t.Fatalf("no per-client cap in the ruleset:\n%s", out)
		}
		var conns []net.Conn
		defer func() {
			for _, c := range conns {
				c.Close()
			}
		}()
		var err error
		for len(conns) < flowCap+100 {
			var c net.Conn
			if c, err = dial(&net.Dialer{Timeout: 2 * time.Second}, siteA, 7002); err != nil {
				break
			}
			conns = append(conns, c)
		}
		// Flows left from earlier subtests (held or half-closed connections, UDP and ping) count too.
		if len(conns) > flowCap || len(conns) < flowCap-100 {
			t.Errorf("opened %d connections before a dial failed (%v); want just under %d", len(conns), err, flowCap)
		}
		t.Logf("opened %d connections; the next dial failed: %v", len(conns), err)
		for _, c := range conns {
			c.Close()
		}
		conns = nil
		// The echo server closes too, so the flows reach TIME_WAIT, which the cap does not count.
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(200 * time.Millisecond) {
			c, err := dial(&net.Dialer{Timeout: time.Second}, siteA, 7002)
			if err == nil {
				c.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("still capped 10 s after closing every connection: %v", err)
			}
		}
	})

	t.Run("detached-translator-fails-closed", func(t *testing.T) {
		// With its programs detached (as after a crash, or by hand), the pair must drop traffic rather than pass it untranslated, and Reassert must notice and repair it.
		if err := inNS(r, func() error {
			ifi, err := net.InterfaceByName(xlat.PrimaryName)
			if err != nil {
				return err
			}
			for _, a := range []ebpf.AttachType{ebpf.AttachNetkitPrimary, ebpf.AttachNetkitPeer} {
				res, err := link.QueryPrograms(link.QueryOptions{Target: ifi.Index, Attach: a})
				if err != nil {
					return err
				}
				for _, p := range res.Programs {
					id, ok := p.LinkID()
					if !ok {
						return fmt.Errorf("%v program %v has no link", a, p.ID)
					}
					l, err := link.NewFromID(id)
					if err != nil {
						return err
					}
					err = l.Detach()
					l.Close()
					if err != nil {
						return fmt.Errorf("detaching link %v: %w", id, err)
					}
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		rxBefore := sh(t, "ip netns exec via64-r cat /sys/class/net/"+xlat.PeerName+"/statistics/rx_packets")
		if c, err := dial(&net.Dialer{Timeout: time.Second}, siteA, 7002); err == nil {
			c.Close()
			t.Error("dial through the pair succeeded with the translator detached")
		}
		if rxAfter := sh(t, "ip netns exec via64-r cat /sys/class/net/"+xlat.PeerName+"/statistics/rx_packets"); rxAfter != rxBefore {
			t.Errorf("%s received packets (%s to %s) with the translator detached", xlat.PeerName, strings.TrimSpace(rxBefore), strings.TrimSpace(rxAfter))
		}
		reassert()
		if !via64.KernelHandles(siteA, ipproto.TCP) {
			t.Fatal("not kernel-handled after Reassert")
		}
		echoTCP(t, siteA)
	})

	t.Run("counters-published", func(t *testing.T) {
		// Reassert copies the translator's counters into client metrics, so drops show without bpftool.
		echoTCP(t, siteA)
		reassert()
		got := map[string]int64{}
		for _, m := range clientmetric.Metrics() {
			got[m.Name()] = m.Value()
		}
		if got["via64_kernel_active"] != 1 || got["via64_xlat_6to4_ok"] == 0 || got["via64_xlat_4to6_ok"] == 0 {
			t.Errorf("client metrics: active %d, 6to4_ok %d, 4to6_ok %d; want 1 and both nonzero", got["via64_kernel_active"], got["via64_xlat_6to4_ok"], got["via64_xlat_4to6_ok"])
		}
	})

	t.Run("forged-x6-from-lan", func(t *testing.T) {
		// A LAN host sending from X6 itself must not get translated. Lift the reverse-path filter and drop policies, as a permissive host has none.
		sh(t, "ip netns exec via64-r nft delete table inet rpf")
		sh(t, "ip netns exec via64-r nft add chain ip6 filter FORWARD { policy accept ; }")
		sh(t, "ip netns exec via64-r nft add chain ip filter FORWARD { policy accept ; }")
		defer func() {
			sh(t, "ip netns exec via64-r nft add chain ip filter FORWARD { policy drop ; }")
			sh(t, "ip netns exec via64-r nft add chain ip6 filter FORWARD { policy drop ; }")
			sh(t, "ip netns exec via64-r nft add table inet rpf")
			sh(t, "ip netns exec via64-r nft add chain inet rpf pre { type filter hook prerouting priority 10 ; }")
			sh(t, "ip netns exec via64-r nft add rule inet rpf pre meta nfproto ipv6 fib saddr . mark . iif oif missing drop")
		}()
		x6 := "fd7a:115c:a1e0:b1a:ff:ffff:c000:6"
		for _, c := range []string{
			"ip -n via64-r addr add fe80::1/64 dev lan0 nodad",
			"ip -n via64-l addr add fe80::3/64 dev eth0 nodad",
			"ip -n via64-l addr add " + x6 + "/128 dev eth0 nodad",
			"ip -n via64-l -6 route add fd7a:115c:a1e0:b1a:ff:ffff::/96 via fe80::1 dev eth0",
		} {
			sh(t, c)
		}
		var sink net.PacketConn
		if err := inNS(lan, func() (err error) { sink, err = net.ListenPacket("udp4", "10.99.0.2:7005"); return err }); err != nil {
			t.Fatal(err)
		}
		defer sink.Close()
		var c net.Conn
		if err := inNS(lan, func() (err error) {
			d := net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP(x6)}}
			c, err = d.Dial("udp6", "[fd7a:115c:a1e0:b1a:ff:ffff:a63:2]:7005")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte("forged"))
		sink.SetDeadline(time.Now().Add(2 * time.Second))
		if n, from, err := sink.ReadFrom(make([]byte, 64)); err == nil {
			t.Errorf("LAN host received %d bytes from %v sent with the forged source X6", n, from)
		}
	})

	t.Run("forged-x4-from-lan", func(t *testing.T) {
		// A LAN host sending from X4 must not have its packets masqueraded into the tailnet as the router. The router's FORWARD chain accepts anything leaving on the tun, as linuxfw's does, and the reverse-path filter is loose or off, as on most distributions.
		for _, c := range []string{
			"ip -n via64-r addr add 100.64.0.1/32 dev tsx0",
			"ip -n via64-r route add 100.64.0.2/32 dev tsx0",
			"ip -n via64-c addr add 100.64.0.2/32 dev eth0",
			"ip -n via64-c route add 100.64.0.1/32 dev eth0",
			"ip -n via64-l addr add 192.0.0.6/32 dev eth0",
			"ip -n via64-l route add 100.64.0.0/10 via 10.99.0.1",
		} {
			sh(t, c)
		}
		var sink net.PacketConn
		if err := inNS(cl, func() (err error) { sink, err = net.ListenPacket("udp4", "100.64.0.2:7006"); return err }); err != nil {
			t.Fatal(err)
		}
		defer sink.Close()
		var c net.Conn
		if err := inNS(lan, func() (err error) {
			d := net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP("192.0.0.6")}}
			c, err = d.Dial("udp4", "100.64.0.2:7006")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte("forged"))
		sink.SetDeadline(time.Now().Add(2 * time.Second))
		if n, from, err := sink.ReadFrom(make([]byte, 64)); err == nil {
			t.Errorf("tailnet client received %d bytes from %v sent by a LAN host with the forged source X4", n, from)
		}
	})

	t.Run("reassert", func(t *testing.T) {
		// Reassert restores a deleted steering rule in place. Open connections keep working, and so does a UDP flow whose first packet arrived while the rule was missing.
		pairIndex := func() int {
			var ifi *net.Interface
			if err := inNS(r, func() (err error) { ifi, err = net.InterfaceByName(xlat.PrimaryName); return err }); err != nil {
				t.Fatal(err)
			}
			return ifi.Index
		}
		before := pairIndex()
		open, err := dial(&net.Dialer{Timeout: 5 * time.Second}, siteA, 7000)
		if err != nil {
			t.Fatal(err)
		}
		defer open.Close()
		echo(t, open)
		var uc *net.UDPConn
		dst := netip.AddrPortFrom(siteA, 7001)
		if udpInKernel {
			if err := inNS(cl, func() (err error) {
				uc, err = net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("fd7a:115c:a1e0::2"), Port: 45002})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			defer uc.Close()
		}

		sh(t, "ip -n via64-r -6 rule del priority 5190")
		if uc != nil {
			uc.WriteToUDPAddrPort([]byte("lost"), dst)
			time.Sleep(100 * time.Millisecond)
		}
		reassert()

		buf := make([]byte, 16)
		if uc != nil {
			uc.SetDeadline(time.Now().Add(3 * time.Second))
			uc.WriteToUDPAddrPort([]byte("again"), dst)
			if n, err := uc.Read(buf); err != nil || string(buf[:n]) != "again" {
				t.Errorf("UDP flow that started while the rule was missing: read %q, %v; want %q", buf[:n], err, "again")
			}
		}
		open.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(open, "still")
		if _, err := io.ReadFull(open, buf[:5]); err != nil || string(buf[:5]) != "still" {
			t.Errorf("connection open across Reassert: echo %q, %v", buf[:5], err)
		}
		if after := pairIndex(); after != before {
			t.Errorf("Reassert recreated %s (index %d, was %d); it should repair only what is missing", xlat.PrimaryName, after, before)
		}
	})

	t.Run("link-down-is-repaired", func(t *testing.T) {
		// Setting either end of the pair down deletes its routes; Reassert sets it up and restores them, keeping open connections.
		for _, dev := range []string{xlat.PrimaryName, xlat.PeerName} {
			open, err := dial(&net.Dialer{Timeout: 5 * time.Second}, siteA, 7000)
			if err != nil {
				t.Fatal(err)
			}
			echo(t, open)
			sh(t, "ip -n via64-r link set "+dev+" down")
			reassert()
			if !via64.KernelHandles(siteA, ipproto.TCP) {
				t.Errorf("%s down: not kernel-handled after Reassert", dev)
			}
			open.SetDeadline(time.Now().Add(5 * time.Second))
			io.WriteString(open, "still")
			buf := make([]byte, 5)
			if _, err := io.ReadFull(open, buf); err != nil || string(buf) != "still" {
				t.Errorf("%s down: connection open across Reassert: echo %q, %v", dev, buf, err)
			}
			open.Close()
			echoTCP(t, siteA)
		}
	})

	t.Run("pair-deleted-is-reinstalled", func(t *testing.T) {
		sh(t, "ip -n via64-r link del "+xlat.PrimaryName)
		reassert()
		if !via64.KernelHandles(siteA, ipproto.TCP) || !via64.KernelHandles(siteB, ipproto.TCP) {
			t.Fatal("not kernel-handled after the pair was deleted and Reassert ran")
		}
		echoTCP(t, siteA)
		echoTCP(t, siteB)
	})

	t.Run("pair-deleted-then-routes-change", func(t *testing.T) {
		// An Update with new routes must reinstall a deleted pair, not fail on it.
		one := desired
		one.Advertised = desired.Advertised[:1]
		sh(t, "ip -n via64-r link del "+xlat.PrimaryName)
		if _, err := update(one); err != nil {
			t.Fatalf("Update with new routes after the pair was deleted: %v", err)
		}
		if _, err := update(desired); err != nil {
			t.Fatal(err)
		}
		echoTCP(t, siteA)
		echoTCP(t, siteB)
	})

	t.Run("survives-ruleset-flush", func(t *testing.T) {
		// After nft flush ruleset, an Update with unchanged routes must reinstall the tables.
		sh(t, "ip netns exec via64-r nft flush ruleset")
		if _, err := update(desired); err != nil {
			t.Fatalf("Update after flush: %v", err)
		}
		echoTCP(t, siteA)
	})

	t.Run("bridge-forward-drop-is-not-ip", func(t *testing.T) {
		// A bridge-family forward chain (ebtables-nft -P FORWARD DROP) filters bridged frames, not routed packets, so it must not stop via64.
		sh(t, "ip netns exec via64-r nft add table bridge brfw")
		sh(t, "ip netns exec via64-r nft add chain bridge brfw forward { type filter hook forward priority 0 ; policy drop ; }")
		defer sh(t, "ip netns exec via64-r nft delete table bridge brfw")
		if got, err := update(desired); err != nil || len(got) != 2 {
			t.Errorf("with a bridge forward drop policy: Update = %v, %v; want both sites", got, err)
		}
	})

	t.Run("other-firewalls-fall-back", func(t *testing.T) {
		// A forward drop policy in a table of its own (Arch's stock nftables.conf), or firewalld, would drop via64's traffic, where netstack needed no forwarding.
		for _, fw := range []struct{ table, chain string }{
			{"userfw", "forward { type filter hook forward priority 0 ; policy drop ; }"},
			{"firewalld", ""},
		} {
			add := func() {
				sh(t, "ip netns exec via64-r nft add table inet "+fw.table)
				if fw.chain != "" {
					sh(t, "ip netns exec via64-r nft add chain inet "+fw.table+" "+fw.chain)
				}
			}
			del := func() { sh(t, "ip netns exec via64-r nft delete table inet "+fw.table) }
			add()
			if got, err := update(desired); err != nil || got != nil || via64.KernelHandles(siteA, ipproto.TCP) {
				t.Errorf("%s: Update = %v, %v; want nothing kernel-handled", fw.table, got, err)
			}
			del()
			if got, err := update(desired); err != nil || len(got) != 2 {
				t.Fatalf("%s removed: Update = %v, %v", fw.table, got, err)
			}
			// Loaded while via64 runs ("systemctl restart nftables"), Reassert hands 4via6 back, and turns it on again once the firewall is gone.
			add()
			reassert()
			if via64.KernelHandles(siteA, ipproto.TCP) {
				t.Errorf("%s: still kernel-handled after Reassert", fw.table)
			}
			del()
			reassert()
			if !via64.KernelHandles(siteA, ipproto.TCP) {
				t.Fatalf("%s removed: not kernel-handled after Reassert", fw.table)
			}
			echoTCP(t, siteA)
		}
	})

	if err := inNS(r, ctl.Close); err != nil {
		t.Fatalf("Close: %v", err)
	}
	closed = true
	if via64.KernelHandles(siteA, ipproto.TCP) {
		t.Error("still kernel-handled after Close")
	}
	if out, err := exec.Command("ip", "-n", "via64-r", "link", "show", xlat.PrimaryName).CombinedOutput(); err == nil {
		t.Errorf("%s still exists after Close:\n%s", xlat.PrimaryName, out)
	}
	// The engine does not serialize a router Set against Close; one arriving after Close must not reinstall anything.
	if got, err := update(desired); got != nil || err != nil {
		t.Errorf("Update after Close = %v, %v; want nothing", got, err)
	}
	if out, err := exec.Command("ip", "-n", "via64-r", "link", "show", xlat.PrimaryName).CombinedOutput(); err == nil {
		t.Errorf("Update after Close recreated %s:\n%s", xlat.PrimaryName, out)
	}
}
