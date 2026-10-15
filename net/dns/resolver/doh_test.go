// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package resolver

import (
	"bytes"
	"context"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"

	miekdns "github.com/miekg/dns"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/health"
	"tailscale.com/net/dns/publicdns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tstest"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/httpm"
)

var testDoH = flag.Bool("test-doh", false, "do real DoH tests against the network")

const someDNSID = 123 // something non-zero as a test; in violation of spec's SHOULD of 0

func someDNSQuestion(t testing.TB) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		OpCode:           0, // query
		RecursionDesired: true,
		ID:               someDNSID,
	})
	b.StartQuestions() // err
	b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName("tailscale.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	})
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestDoH(t *testing.T) {
	if !*testDoH {
		t.Skip("skipping manual test without --test-doh flag")
	}
	prefixes := publicdns.KnownDoHPrefixes()
	if len(prefixes) == 0 {
		t.Fatal("no known DoH")
	}

	f := &forwarder{}

	for _, urlBase := range prefixes {
		t.Run(urlBase, func(t *testing.T) {
			c, ok := f.getKnownDoHClientForProvider(urlBase)
			if !ok {
				t.Fatal("expected DoH")
			}
			res, err := f.sendDoH(context.Background(), urlBase, c, someDNSQuestion(t))
			if err != nil {
				t.Fatal(err)
			}
			c.Transport.(*http.Transport).CloseIdleConnections()

			// Contents of DoHMeta are tested in TestDoHMeta.
			if res.DoHMeta == nil {
				t.Errorf("expected DoHMeta")
			}

			var p dnsmessage.Parser
			h, err := p.Start(res.Bs)
			if err != nil {
				t.Fatal(err)
			}
			if h.ID != someDNSID {
				t.Errorf("response DNS ID = %v; want %v", h.ID, someDNSID)
			}

			p.SkipAllQuestions()
			aa, err := p.AllAnswers()
			if err != nil {
				t.Fatal(err)
			}
			if len(aa) == 0 {
				t.Fatal("no answers")
			}
			for _, r := range aa {
				t.Logf("got: %v", r.GoString())
			}
		})
	}
}

func TestDoHV6Fallback(t *testing.T) {
	for _, base := range publicdns.KnownDoHPrefixes() {
		for _, ip := range publicdns.DoHIPsOfBase(base) {
			if ip.Is4() {
				ip6, ok := publicdns.DoHV6(base)
				if !ok {
					t.Errorf("no v6 DoH known for %v", ip)
				} else if !ip6.Is6() {
					t.Errorf("dohV6(%q) returned non-v6 address %v", base, ip6)
				}
			}
		}
	}
}

func TestGetDoHClientForResolver(t *testing.T) {
	var fwd forwarder

	// Known public providers work without a bootstrap resolution.
	if _, ok := fwd.getDoHClientForResolver(&dnstype.Resolver{Addr: "https://dns.google/dns-query"}); !ok {
		t.Fatal("known provider without bootstrap not ok")
	}

	// Arbitrary providers with a hostname and no bootstrap resolution get a
	// client that looks the hostname up at dial time.
	arbitrary := "https://doh.corp.example/query"
	if _, ok := fwd.getDoHClientForResolver(&dnstype.Resolver{Addr: arbitrary}); !ok {
		t.Fatal("arbitrary provider without bootstrap not ok")
	}
	if _, ok := fwd.getDoHClientForResolver(&dnstype.Resolver{Addr: "https://[invalid/query"}); ok {
		t.Fatal("unparseable DoH URL unexpectedly ok")
	}

	// A URL whose host is an IP literal dials itself; no bootstrap resolution
	// is needed.
	for _, ipURL := range []string{
		"https://192.0.2.53:8443/dns-query",
		"https://[2001:db8::53]/dns-query",
	} {
		if _, ok := fwd.getDoHClientForResolver(&dnstype.Resolver{Addr: ipURL}); !ok {
			t.Errorf("IP-literal DoH URL %q not usable without bootstrap", ipURL)
		}
	}

	bootstrap := []netip.Addr{netip.MustParseAddr("10.0.0.53")}
	c, ok := fwd.getDoHClientForResolver(&dnstype.Resolver{Addr: arbitrary, BootstrapResolution: bootstrap})
	if !ok {
		t.Fatal("arbitrary provider with bootstrap not ok")
	}
	c2, ok := fwd.getDoHClientForResolver(&dnstype.Resolver{Addr: arbitrary, BootstrapResolution: bootstrap})
	if !ok || c != c2 {
		t.Fatal("bootstrap client not cached")
	}
	// A changed bootstrap must produce a distinct client, not reuse the one
	// pinned to the old IPs.
	c3, ok := fwd.getDoHClientForResolver(&dnstype.Resolver{
		Addr:                arbitrary,
		BootstrapResolution: []netip.Addr{netip.MustParseAddr("10.0.0.54")},
	})
	if !ok {
		t.Fatal("no client for changed bootstrap")
	}
	if c3 == c {
		t.Errorf("changed bootstrap reused the client pinned to the old IPs")
	}
}

// TestSendArbitraryDoHWithBootstrap verifies that send() dispatches an
// arbitrary (non-publicdns) https:// resolver with a bootstrap resolution
// through the DoH transport, as used for upstreams recovered from the OS's
// base DNS configuration.
func TestSendArbitraryDoHWithBootstrap(t *testing.T) {
	var gotRequests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != httpm.POST {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != dohType {
			t.Errorf("query Content-Type = %q; want %q", ct, dohType)
		}
		gotRequests.Add(1)
		w.Header().Set("Content-Type", dohType)
		w.Write(body)
	}))
	defer srv.Close()

	urlBase := srv.URL + "/dns-query"
	if ips := publicdns.DoHIPsOfBase(urlBase); len(ips) > 0 {
		t.Fatalf("%q unexpectedly a known provider", urlBase)
	}

	logf := tstest.WhileTestRunningLogger(t)
	bus := eventbustest.NewBus(t)
	netMon, err := netmon.New(bus, logf)
	if err != nil {
		t.Fatal(err)
	}
	var dialer tsdial.Dialer
	dialer.SetNetMon(netMon)
	dialer.SetBus(bus)
	fwd := newForwarder(logf, netMon, nil, &dialer, health.NewTracker(bus), nil)

	bootstrap := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	r := &dnstype.Resolver{Addr: urlBase, BootstrapResolution: bootstrap}

	// Inject the test server's client at the cache key send() computes for
	// this resolver; the httptest client accepts the local certificate.
	fwd.mu.Lock()
	fwd.dohClient = map[string]*http.Client{
		dohClientCacheKey(urlBase, bootstrap): srv.Client(),
	}
	fwd.mu.Unlock()

	fq := &forwardQuery{txid: someDNSID, packet: someDNSQuestion(t), family: "udp"}
	res, err := fwd.send(context.Background(), fq, resolverAndDelay{name: r})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !bytes.Equal(res.Bs, fq.packet) {
		t.Errorf("response = %x; want echoed query", res.Bs)
	}
	if got := gotRequests.Load(); got != 1 {
		t.Errorf("saw %d requests; want 1", got)
	}
}

func TestDoHLookupResolvers(t *testing.T) {
	const doh = "https://doh.corp.example/q"
	tests := []struct {
		name       string
		routes     map[dnsname.FQDN][]*dnstype.Resolver
		bootstrap  []*dnstype.Resolver
		wantRouted bool
		want       []string // resolver Addrs
	}{
		{
			// The OS does not send unrouted names to quad-100, so the OS resolver can look them up.
			name:   "unrouted",
			routes: map[dnsname.FQDN][]*dnstype.Resolver{"other.example.": {{Addr: doh}}},
		},
		{
			// Resolvers that need a lookup of their own, and quad-100, are skipped.
			name:       "route-has-other-resolver",
			routes:     map[dnsname.FQDN][]*dnstype.Resolver{".": {{Addr: doh}, {Addr: "https://doh2.corp.example/q"}, {Addr: "100.100.100.100"}, {Addr: "192.0.2.53"}}},
			wantRouted: true,
			want:       []string{"192.0.2.53"},
		},
		{
			name:       "global-doh",
			routes:     map[dnsname.FQDN][]*dnstype.Resolver{".": {{Addr: doh}}},
			wantRouted: true,
		},
		{
			// A DoH global nameserver uses the OS's resolvers.
			name:       "global-doh-uses-bootstrap",
			routes:     map[dnsname.FQDN][]*dnstype.Resolver{".": {{Addr: doh}}},
			bootstrap:  []*dnstype.Resolver{{Addr: "100.100.100.100"}, {Addr: "192.0.2.1"}},
			wantRouted: true,
			want:       []string{"192.0.2.1"},
		},
		{
			// The DoH server's name is under the split domain that it serves, so the lookup falls through to the "." route.
			name:       "under-own-split-route",
			routes:     map[dnsname.FQDN][]*dnstype.Resolver{"corp.example.": {{Addr: doh}}, ".": {{Addr: "192.0.2.53"}}},
			bootstrap:  []*dnstype.Resolver{{Addr: "192.0.2.1"}},
			wantRouted: true,
			want:       []string{"192.0.2.53"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd := newTestForwarder(t, nil)
			fwd.setRoutes(tt.routes, true)
			fwd.setDoHBootstrapResolvers(tt.bootstrap)
			rs, routed := fwd.dohLookupResolvers("doh.corp.example.")
			if routed != tt.wantRouted {
				t.Errorf("routed = %v; want %v", routed, tt.wantRouted)
			}
			var got []string
			for _, rr := range rs {
				got = append(got, rr.name.Addr)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("resolvers = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestDoHHostDialer(t *testing.T) {
	loopback := netip.MustParseAddr("127.0.0.1")

	// Dials to ln complete without an Accept, which is all these tests need.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	closed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	_, closedPort, _ := net.SplitHostPort(closed.Addr().String())

	var queries atomic.Int32
	server := serveDNS(t, "127.0.0.1:0", ".", miekdns.HandlerFunc(func(w miekdns.ResponseWriter, req *miekdns.Msg) {
		queries.Add(1)
		dnsHandler(loopback)(w, req)
	}))
	defer server.Shutdown()
	nameserver := server.PacketConn.LocalAddr().String()

	t.Run("forwarded", func(t *testing.T) {
		queries.Store(0)
		fwd := newTestForwarder(t, nil)
		fwd.setRoutes(map[dnsname.FQDN][]*dnstype.Resolver{".": {{Addr: "https://doh.example.com/dns-query"}, {Addr: nameserver}}}, true)
		dial := fwd.newDoHHostDialer("doh.example.com")
		mustDial := func(wantQueries int32) {
			t.Helper()
			c, err := dial(t.Context(), "tcp", "doh.example.com:"+port)
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
			if got := queries.Load(); got != wantQueries {
				t.Errorf("nameserver got %d queries; want %d", got, wantQueries)
			}
		}
		failDial := func() {
			t.Helper()
			if c, err := dial(t.Context(), "tcp", "doh.example.com:"+closedPort); err == nil {
				c.Close()
				t.Fatal("dial to a closed port succeeded")
			}
		}

		mustDial(2) // one query each for A and AAAA
		mustDial(2) // reused
		failDial()
		mustDial(4) // looked up again after the failed dial

		// With no way to look the name up, the last addresses are used.
		fwd.setRoutes(map[dnsname.FQDN][]*dnstype.Resolver{".": {{Addr: "https://doh.example.com/dns-query"}}}, true)
		failDial()
		mustDial(4)
	})

	t.Run("magicdns", func(t *testing.T) {
		queries.Store(0)
		r := newResolver(t)
		defer r.Close()
		r.SetConfig(Config{
			Routes:       map[dnsname.FQDN][]*dnstype.Resolver{".": {{Addr: "https://doh.tail-net.ts.net/dns-query"}, {Addr: nameserver}}},
			Hosts:        map[dnsname.FQDN][]netip.Addr{"doh.tail-net.ts.net.": {loopback}},
			LocalDomains: []dnsname.FQDN{"tail-net.ts.net."},
		})
		for host, wantOK := range map[string]bool{"doh.tail-net.ts.net": true, "missing.tail-net.ts.net": false} {
			c, err := r.forwarder.newDoHHostDialer(host)(t.Context(), "tcp", net.JoinHostPort(host, port))
			if (err == nil) != wantOK {
				t.Errorf("dialing %s: err = %v; want ok %v", host, err, wantOK)
			}
			if c != nil {
				c.Close()
			}
		}
		// quad-100 is authoritative for tail-net.ts.net, so even names that it does not know are not asked of anyone else.
		if got := queries.Load(); got != 0 {
			t.Errorf("nameserver got %d queries; want 0", got)
		}
	})
}
