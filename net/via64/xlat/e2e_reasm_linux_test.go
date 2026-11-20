// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package xlat_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/via64"
	"tailscale.com/net/via64/xlat"
	"tailscale.com/net/via64/xlatbpf"
	"tailscale.com/tstest"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/preftype"
	"tailscale.com/types/views"
	"tailscale.com/wgengine/filter"
)

// openTUN creates the TUN device name in ns and returns it, non-blocking so that closing it ends a pending Read.
func openTUN(t *testing.T, ns netns.NsHandle, name string) *os.File {
	t.Helper()
	var f *os.File
	err := inNS(ns, func() error {
		fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		ifr, err := unix.NewIfreq(name)
		if err != nil {
			unix.Close(fd)
			return err
		}
		ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
		if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
			unix.Close(fd)
			return err
		}
		if err := unix.SetNonblock(fd, true); err != nil {
			unix.Close(fd)
			return err
		}
		f = os.NewFile(uintptr(fd), name)
		return nil
	})
	if err != nil {
		t.Fatalf("creating TUN %s: %v", name, err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

/*
tailscaledStandIn carries packets between the client's and the router's TUN devices the way tailscaled does for 4via6 the kernel translates: from the client, the packet filter runs on each packet (tstun), then IPv6 fragments of UDP to a kernel-handled via address go to a via64.Reassembler and the filter runs again on the whole datagram before it is written to the router's TUN (netstack's reassembleForVia64). With reassemble off it passes fragments through one by one, as before.
*/
type tailscaledStandIn struct {
	filt       *filter.Filter
	reassemble atomic.Bool
	r          via64.Reassembler
	filtered   atomic.Int64 // packets or datagrams the filter dropped
	whole      atomic.Int64 // reassembled datagrams written
}

func (s *tailscaledStandIn) fromClient(pkt []byte) []byte {
	var q packet.Parsed
	q.Decode(pkt)
	if s.filt.RunIn(&q, 0) != filter.Accept {
		s.filtered.Add(1)
		return nil
	}
	if !s.reassemble.Load() || !via64.KernelReassembles(pkt) {
		return pkt
	}
	b := s.r.Add(pkt)
	if b == nil {
		return nil
	}
	q.Decode(b)
	if s.filt.RunIn(&q, 0) != filter.Accept {
		s.filtered.Add(1)
		return nil
	}
	s.whole.Add(1)
	return b
}

func pump(from, to *os.File, fn func([]byte) []byte) {
	buf := make([]byte, 65536)
	for {
		n, err := from.Read(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		if fn != nil {
			if pkt = fn(pkt); pkt == nil {
				continue
			}
		}
		to.Write(pkt)
	}
}

var nftCounterRE = regexp.MustCompile(`counter packets (\d+) bytes \d+ comment "(\w+)"`)

// TestEndToEndReassembly checks client UDP fragments reach the LAN as whole datagrams once tailscaled reassembles them. Unlike TestEndToEnd, tailscale0 is a real TUN device on the router, fed by a stand-in for tailscaled, since the kernel must accept datagrams over its MTU from it.
func TestEndToEndReassembly(t *testing.T) {
	tstest.RequireRoot(t)
	r := addNetNS(t, "via64-fr")
	cl := addNetNS(t, "via64-fc")
	lan := addNetNS(t, "via64-fl")
	rTUN := openTUN(t, r, "tsx0")
	cTUN := openTUN(t, cl, "eth0")
	for _, cmd := range []string{
		"ip -n via64-fr link set tsx0 mtu 1280 up",
		"ip -n via64-fr addr add fe80::1/64 dev tsx0 nodad",
		// Stand-in for Tailscale's table 52.
		"ip -n via64-fr -6 route add fd7a:115c:a1e0::/48 dev tsx0",
		"ip link add lan0 netns via64-fr mtu 9000 type veth peer name eth0 netns via64-fl mtu 9000",
		"ip -n via64-fr addr add 10.99.0.1/24 dev lan0",
		"ip -n via64-fr link set lan0 up",
		"ip netns exec via64-fr sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1",
		"ip -n via64-fc link set eth0 mtu 1280 up",
		"ip -n via64-fc addr add fd7a:115c:a1e0::2/128 dev eth0 nodad",
		"ip -n via64-fc -6 route add fd7a:115c:a1e0:b1a::/64 dev eth0",
		"ip -n via64-fl addr add 10.99.0.2/24 dev eth0",
		"ip -n via64-fl link set eth0 up",
		// What arrives at the LAN host, before any reassembly.
		"ip netns exec via64-fl nft add table netdev cap",
		"ip netns exec via64-fl nft add chain netdev cap in { type filter hook ingress device eth0 priority 0 ; }",
		"ip netns exec via64-fl nft add rule netdev cap in ip frag-off & 0x3fff != 0 counter comment frags",
		"ip netns exec via64-fl nft add rule netdev cap in ip frag-off & 0x3fff == 0 udp dport 7001 counter comment whole",
		"ip netns exec via64-fl nft add rule netdev cap in ip frag-off & 0x4000 != 0 udp dport 7001 counter comment df",
	} {
		sh(t, cmd)
	}

	siteA := via(0x1790, "10.99.0.2")
	client := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	var sb netipx.IPSetBuilder
	sb.AddPrefix(tsaddr.TailscaleViaRange())
	local, _ := sb.IPSet()
	ts := &tailscaledStandIn{
		// UDP to ports 7001 to 7010 and iperf3's 5201 (with its TCP control connection); not 7099.
		filt: filter.New([]filter.Match{
			{
				IPProto: views.SliceOf([]ipproto.Proto{ipproto.UDP}),
				Srcs:    []netip.Prefix{client},
				Dsts:    []filter.NetPortRange{{Net: tsaddr.TailscaleViaRange(), Ports: filter.PortRange{First: 7001, Last: 7010}}},
			},
			{
				IPProto: views.SliceOf([]ipproto.Proto{ipproto.UDP, ipproto.TCP}),
				Srcs:    []netip.Prefix{client},
				Dsts:    []filter.NetPortRange{{Net: tsaddr.TailscaleViaRange(), Ports: filter.PortRange{First: 5201, Last: 5201}}},
			},
		}, nil, local, local, nil, t.Logf),
	}
	ts.reassemble.Store(true)
	go pump(cTUN, rTUN, ts.fromClient)
	go pump(rTUN, cTUN, nil)

	ctl := xlat.NewController(xlat.Config{
		Ingress:      "tsx0",
		RulePriority: 5190,
		Table:        5264,
		X4:           netip.MustParseAddr("192.0.0.6"),
		NewBackend:   xlatbpf.New,
		Logf:         t.Logf,
	})
	var handled []netip.Prefix
	var err error
	inNS(r, func() error {
		handled, err = ctl.Update(xlat.Desired{Netfilter: preftype.NetfilterOn, SNAT: true, TunIPv6: true, Advertised: []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:1790::/96")}})
		return nil
	})
	if err != nil || len(handled) != 1 {
		t.Fatalf("Update = %v, %v", handled, err)
	}
	t.Cleanup(func() { inNS(r, ctl.Close) })
	if !via64.KernelHandles(siteA, ipproto.UDP) {
		t.Skip("UDP stays on netstack on this kernel, which this test does not run")
	}

	type rx struct {
		n    int
		from string
	}
	got := make(chan rx, 16)
	var echoConn, deniedConn net.PacketConn
	if err := inNS(lan, func() (err error) {
		// Replies without DF, so they reach the client as fragments, as through netstack (TestEndToEnd/udp-df-reply covers DF).
		if echoConn, err = listenPMTU("10.99.0.2:7001", unix.IP_PMTUDISC_DONT); err != nil {
			return err
		}
		deniedConn, err = net.ListenPacket("udp4", "10.99.0.2:7099")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echoConn.Close(); deniedConn.Close() })
	go func() {
		buf := make([]byte, 65536)
		for {
			n, a, err := echoConn.ReadFrom(buf)
			if err != nil {
				return
			}
			select {
			case got <- rx{n, a.String()}:
			default:
			}
			echoConn.WriteTo(buf[:n], a)
		}
	}()
	var deniedGot atomic.Int64
	go func() {
		buf := make([]byte, 65536)
		for {
			if _, _, err := deniedConn.ReadFrom(buf); err != nil {
				return
			}
			deniedGot.Add(1)
		}
	}()

	counters := func(t *testing.T) map[string]int {
		t.Helper()
		m := map[string]int{}
		for _, s := range nftCounterRE.FindAllStringSubmatch(sh(t, "ip netns exec via64-fl nft list chain netdev cap in"), -1) {
			m[s[2]], _ = strconv.Atoi(s[1])
		}
		return m
	}
	dialUDP := func(t *testing.T, port uint16) net.Conn {
		t.Helper()
		var c net.Conn
		if err := inNS(cl, func() (err error) { c, err = net.Dial("udp6", netip.AddrPortFrom(siteA, port).String()); return err }); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	// roundTrip sends a datagram of size bytes and waits for its echo, returning what the LAN host saw.
	roundTrip := func(t *testing.T, c net.Conn, size int) rx {
		t.Helper()
		for len(got) > 0 {
			<-got
		}
		msg := bytes.Repeat([]byte{byte(size)}, size)
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(msg); err != nil {
			t.Fatalf("%d bytes: write: %v", size, err)
		}
		buf := make([]byte, 65536)
		n, err := c.Read(buf)
		if err != nil || !bytes.Equal(buf[:n], msg) {
			t.Fatalf("%d bytes: echo of %d bytes, %v", size, n, err)
		}
		select {
		case x := <-got:
			return x
		case <-time.After(time.Second):
			t.Fatalf("%d bytes: the LAN host saw nothing", size)
		}
		return rx{}
	}

	t.Run("whole-on-lan", func(t *testing.T) {
		c := dialUDP(t, 7001)
		for _, size := range []int{1300, 1342, 1400, 2000, 8000} {
			before, w0 := counters(t), ts.whole.Load()
			x := roundTrip(t, c, size)
			after := counters(t)
			if x.n != size {
				t.Errorf("%d bytes: the LAN host received %d", size, x.n)
			}
			// One unfragmented IPv4 packet (offset 0, MF 0), without DF.
			if d := after["frags"] - before["frags"]; d != 0 {
				t.Errorf("%d bytes: %d IPv4 fragments reached the LAN host; want 0", size, d)
			}
			if d := after["whole"] - before["whole"]; d != 1 {
				t.Errorf("%d bytes: %d unfragmented packets reached the LAN host; want 1", size, d)
			}
			if d := after["df"] - before["df"]; d != 0 {
				t.Errorf("%d bytes: %d packets with DF; want 0", size, d)
			}
			if d := ts.whole.Load() - w0; d != 1 {
				t.Errorf("%d bytes: tailscaled reassembled %d datagrams; want 1", size, d)
			}
		}
	})

	t.Run("same-flow", func(t *testing.T) {
		// Small and large datagrams from one socket share the flow, and so its masquerade address and port.
		c := dialUDP(t, 7001)
		var froms []string
		for _, size := range []int{100, 1342, 100, 2000, 100} {
			froms = append(froms, roundTrip(t, c, size).from)
		}
		for _, f := range froms[1:] {
			if f != froms[0] {
				t.Errorf("the LAN host saw the client as %v; want one address and port", froms)
				break
			}
		}
	})

	// A LAN host that rejects IPv4 fragments with "port unreachable", as Cloudflare does with QUIC.
	sh(t, "ip netns exec via64-fl nft add table ip cf")
	sh(t, "ip netns exec via64-fl nft add chain ip cf pre { type filter hook prerouting priority -500 ; }")
	sh(t, "ip netns exec via64-fl nft add rule ip cf pre ip frag-off & 0x3fff != 0 udp dport 7001 reject with icmp port-unreachable")
	sh(t, "ip netns exec via64-fl nft add rule ip cf pre ip frag-off & 0x3fff != 0 drop")

	t.Run("fragment-rejecting-host-without-reassembly", func(t *testing.T) {
		// The failure the reassembly fixes: forwarded one by one, the fragments reach the LAN host as IPv4 fragments, and the client's socket gets ECONNREFUSED.
		ts.reassemble.Store(false)
		defer ts.reassemble.Store(true)
		c := dialUDP(t, 7001)
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write(bytes.Repeat([]byte("q"), 1342))
		if _, err := c.Read(make([]byte, 2048)); !errors.Is(err, syscall.ECONNREFUSED) {
			t.Errorf("read: %v; want ECONNREFUSED", err)
		}
	})
	t.Run("fragment-rejecting-host", func(t *testing.T) {
		c := dialUDP(t, 7001)
		for _, size := range []int{100, 1342, 1400} {
			roundTrip(t, c, size)
		}
	})
	sh(t, "ip netns exec via64-fl nft delete table ip cf")

	t.Run("filter-denies-port", func(t *testing.T) {
		f0 := ts.filtered.Load()
		c := dialUDP(t, 7099)
		c.Write(bytes.Repeat([]byte("d"), 2000)) // the filter drops its first fragment; the later one waits in vain
		c.Write([]byte("small"))
		time.Sleep(time.Second)
		if n := deniedGot.Load(); n != 0 {
			t.Errorf("the LAN host received %d datagrams on a port the client is not granted", n)
		}
		if d := ts.filtered.Load() - f0; d != 2 {
			t.Errorf("the filter dropped %d packets; want 2 (the first fragment and the small datagram)", d)
		}
	})

	t.Run("iperf3", func(t *testing.T) {
		if os.Getenv("VIA64_IPERF3") == "" {
			t.Skip("set VIA64_IPERF3=1 to measure UDP throughput through the router")
		}
		if _, err := exec.LookPath("iperf3"); err != nil {
			t.Skip("iperf3 is not installed")
		}
		srv := exec.Command("ip", "netns", "exec", "via64-fl", "iperf3", "-s", "-B", "10.99.0.2", "-p", "5201")
		if err := srv.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { srv.Process.Kill(); srv.Wait() }()
		time.Sleep(500 * time.Millisecond)
		for _, reasm := range []bool{false, true} {
			ts.reassemble.Store(reasm)
			for _, size := range []string{"1200", "1400"} {
				out, err := exec.Command("ip", "netns", "exec", "via64-fc", "iperf3", "-6", "-c", siteA.String(), "-p", "5201", "-u", "-b", "300M", "-l", size, "-t", "10", "-J").Output()
				if err != nil {
					t.Fatalf("iperf3: %v\n%s", err, out)
				}
				type sum struct {
					BitsPerSecond float64 `json:"bits_per_second"`
					LostPercent   float64 `json:"lost_percent"`
					Packets       int     `json:"packets"`
				}
				var res struct {
					End struct {
						Sum         sum `json:"sum"`
						SumReceived sum `json:"sum_received"`
					} `json:"end"`
				}
				if err := json.Unmarshal(out, &res); err != nil {
					t.Fatal(err)
				}
				s, rcv := res.End.Sum, res.End.SumReceived
				t.Logf("reassemble=%v -l %s: sent %.1f Mbit/s, received %.1f Mbit/s, %.2f%% of %d datagrams lost", reasm, size, s.BitsPerSecond/1e6, rcv.BitsPerSecond/1e6, s.LostPercent, s.Packets)
			}
		}
		ts.reassemble.Store(true)
	})
}
