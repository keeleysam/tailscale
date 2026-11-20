// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"go4.org/netipx"
	"tailscale.com/ipn"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/via64"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/views"
	"tailscale.com/util/clientmetric"
	"tailscale.com/wgengine/filter"
)

// via64Frags returns the IPv6 fragments, of at most 1232 bytes of fragmentable part each, of a UDP datagram with n bytes of payload from src to dst, with Next Header nh in their Fragment Headers.
func via64Frags(src, dst netip.AddrPort, n int, nh ipproto.Proto) [][]byte {
	part := make([]byte, 8+n)
	binary.BigEndian.PutUint16(part[0:], src.Port())
	binary.BigEndian.PutUint16(part[2:], dst.Port())
	binary.BigEndian.PutUint16(part[4:], uint16(len(part)))
	binary.BigEndian.PutUint16(part[6:], 0xffff)
	var fs [][]byte
	for off := 0; off < len(part); off += 1232 {
		end := min(off+1232, len(part))
		b := make([]byte, 48+end-off)
		b[0] = 0x60
		binary.BigEndian.PutUint16(b[4:], uint16(8+end-off))
		b[6], b[7] = 44, 64
		s, d := src.Addr().As16(), dst.Addr().As16()
		copy(b[8:], s[:])
		copy(b[24:], d[:])
		b[40] = byte(nh)
		offlg := uint16(off)
		if end < len(part) {
			offlg |= 1
		}
		binary.BigEndian.PutUint16(b[42:], offlg)
		binary.BigEndian.PutUint32(b[44:], 0x5eed)
		copy(b[48:], part[off:end])
		fs = append(fs, b)
	}
	return fs
}

func metricValue(name string) int64 {
	for _, m := range clientmetric.Metrics() {
		if m.Name() == name {
			return m.Value()
		}
	}
	return 0
}

// TestInjectInboundReassemblesVia64UDP checks that fragments of UDP datagrams to a via prefix the kernel translates are reassembled and filtered as whole datagrams rather than passed to the kernel one by one.
func TestInjectInboundReassemblesVia64UDP(t *testing.T) {
	t.Cleanup(func() { via64.SetKernelHandled(nil, true) })
	impl := makeNetstack(t, nil)
	prefs := ipn.NewPrefs()
	prefs.AdvertiseRoutes = []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:7:a01:100/120")}
	impl.lb.Start(ipn.Options{UpdatePrefs: prefs})
	impl.atomicIsLocalIPFunc.Store(looksLikeATailscaleSelfAddress)
	via64.SetKernelHandled(prefs.AdvertiseRoutes, true)

	var sb netipx.IPSetBuilder
	sb.AddPrefix(tsaddr.TailscaleViaRange())
	local, _ := sb.IPSet()
	impl.tundev.SetFilter(filter.New([]filter.Match{{
		IPProto: views.SliceOf([]ipproto.Proto{ipproto.UDP}),
		Srcs:    []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0::/48")},
		Dsts:    []filter.NetPortRange{{Net: tsaddr.TailscaleViaRange(), Ports: filter.PortRange{First: 5678, Last: 5678}}},
	}}, nil, local, local, nil, t.Logf))

	src := netip.MustParseAddrPort("[fd7a:115c:a1e0::123]:1234")
	allowed := netip.MustParseAddrPort("[fd7a:115c:a1e0:b1a:0:7:a01:109]:5678")
	denied := netip.AddrPortFrom(allowed.Addr(), 5679)
	inject := func(b []byte) filter.Response {
		var p packet.Parsed
		p.Decode(b)
		resp, _ := impl.injectInbound(&p, impl.tundev, nil)
		return resp
	}
	ok0, filt0, err0 := metricValue("via64_reasm_ok"), metricValue("via64_reasm_drop_filter"), metricValue("via64_reasm_drop_error")

	for i, f := range via64Frags(src, allowed, 3000, ipproto.UDP) {
		if resp := inject(f); resp != filter.DropSilently {
			t.Errorf("UDP fragment %d: %v; want DropSilently (taken for reassembly)", i, resp)
		}
	}
	if got := metricValue("via64_reasm_ok") - ok0; got != 1 {
		t.Errorf("via64_reasm_ok grew by %d; want 1", got)
	}
	if got := metricValue("via64_reasm_drop_error") - err0; got != 0 {
		t.Errorf("via64_reasm_drop_error grew by %d; want 0 (injecting the datagram failed)", got)
	}

	// The tstun filter would drop this first fragment; past it, the filter on the whole datagram drops it.
	for _, f := range via64Frags(src, denied, 3000, ipproto.UDP) {
		inject(f)
	}
	if got := metricValue("via64_reasm_drop_filter") - filt0; got != 1 {
		t.Errorf("via64_reasm_drop_filter grew by %d; want 1", got)
	}

	// TCP fragments still go to the kernel one by one.
	for i, f := range via64Frags(src, allowed, 3000, ipproto.TCP) {
		if resp := inject(f); resp != filter.Accept {
			t.Errorf("TCP fragment %d: %v; want Accept (to the kernel)", i, resp)
		}
	}
	// So does UDP with UDP on netstack: there netstack reassembles it.
	via64.SetKernelHandled(prefs.AdvertiseRoutes, false)
	if resp := inject(via64Frags(src, allowed, 3000, ipproto.UDP)[0]); resp != filter.DropSilently {
		t.Errorf("UDP fragment with UDP on netstack: %v; want DropSilently (netstack)", resp)
	}
	if got := metricValue("via64_reasm_ok") - ok0; got != 2 { // both reassembled datagrams, the filtered one included
		t.Errorf("via64_reasm_ok grew by %d; want 2", got)
	}
}
