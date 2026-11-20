// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package via64

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/types/ipproto"
	"tailscale.com/util/clientmetric"
)

var (
	testSrc = netip.MustParseAddr("fd7a:115c:a1e0::2")
	testDst = netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:1790:a63:2")
)

// udp6 returns an IPv6 UDP packet from src to dst with n bytes of payload.
func udp6(src, dst netip.Addr, n int) []byte {
	b := make([]byte, ipv6HeaderLen+udpHeaderLen+n)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(udpHeaderLen+n))
	b[6] = byte(ipproto.UDP)
	b[7] = 64
	s, d := src.As16(), dst.As16()
	copy(b[8:], s[:])
	copy(b[24:], d[:])
	binary.BigEndian.PutUint16(b[40:], 5555)
	binary.BigEndian.PutUint16(b[42:], 7001)
	binary.BigEndian.PutUint16(b[44:], uint16(udpHeaderLen+n))
	binary.BigEndian.PutUint16(b[46:], 0x1234) // not checked
	for i := range n {
		b[48+i] = byte(i)
	}
	return b
}

// frag returns the fragment of whole (an unfragmented IPv6 packet) holding its fragmentable part's bytes [off, end), with Identification id.
func frag(whole []byte, id uint32, off, end int) []byte {
	part := whole[ipv6HeaderLen:]
	b := make([]byte, ipv6HeaderLen+fragHeaderLen+end-off)
	copy(b, whole[:ipv6HeaderLen])
	b[6] = fragHeaderProto
	binary.BigEndian.PutUint16(b[4:], uint16(fragHeaderLen+end-off))
	b[40] = whole[6]
	offlg := uint16(off)
	if end < len(part) {
		offlg |= 1
	}
	binary.BigEndian.PutUint16(b[42:], offlg)
	binary.BigEndian.PutUint32(b[44:], id)
	copy(b[48:], part[off:end])
	return b
}

// split cuts whole into fragments of at most size bytes of its fragmentable part, as a host with a 1280-byte MTU does with size 1232.
func split(whole []byte, id uint32, size int) [][]byte {
	var fs [][]byte
	n := len(whole) - ipv6HeaderLen
	for off := 0; off < n; off += size {
		fs = append(fs, frag(whole, id, off, min(off+size, n)))
	}
	return fs
}

type counts map[*clientmetric.Metric]int64

func snapshot() counts {
	c := counts{}
	for _, m := range []*clientmetric.Metric{metricReasmOK, metricReasmTimeout, metricReasmDropOverlap, metricReasmDropInvalid, metricReasmDropSize, metricReasmDropLimit} {
		c[m] = m.Value()
	}
	return c
}

// delta checks that only the metrics in want changed since c, by those amounts.
func (c counts) delta(t *testing.T, want map[*clientmetric.Metric]int64) {
	t.Helper()
	for m, before := range c {
		if got := m.Value() - before; got != want[m] {
			t.Errorf("%s grew by %d; want %d", m.Name(), got, want[m])
		}
	}
}

func checkEmpty(t *testing.T, r *Reassembler) {
	t.Helper()
	if n, b := r.stats(); n != 0 || b != 0 {
		t.Errorf("%d reassemblies pending with %d bytes; want none", n, b)
	}
}

func TestReassemble(t *testing.T) {
	for _, tc := range []struct {
		name  string
		size  int   // UDP payload
		order []int // fragment indexes in arrival order; nil means in order
	}{
		{"2-in-order", 1342 - 48, nil},
		{"2-reversed", 1342 - 48, []int{1, 0}},
		{"7-mixed", 8000, []int{3, 6, 0, 5, 1, 4, 2}},
		{"53-in-order", 65000, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Reassembler{Headroom: 16}
			c := snapshot()
			whole := udp6(testSrc, testDst, tc.size)
			fs := split(whole, 0xabcd0001, 1232)
			order := tc.order
			if order == nil {
				for i := range fs {
					order = append(order, i)
				}
			}
			var got []byte
			for i, fi := range order {
				out := r.Add(fs[fi])
				if i < len(order)-1 && out != nil {
					t.Fatalf("Add returned a packet after %d of %d fragments", i+1, len(fs))
				}
				got = out
			}
			if got == nil {
				t.Fatal("no packet after the last fragment")
			}
			if !bytes.Equal(got[16:], whole) {
				t.Errorf("reassembled %d bytes, differing from the %d-byte original", len(got)-16, len(whole))
			}
			c.delta(t, map[*clientmetric.Metric]int64{metricReasmOK: 1})
			checkEmpty(t, r)
		})
	}
}

func TestReassembleAtomicFragment(t *testing.T) {
	r := &Reassembler{}
	whole := udp6(testSrc, testDst, 100)
	if got := r.Add(frag(whole, 1, 0, len(whole)-ipv6HeaderLen)); !bytes.Equal(got, whole) {
		t.Errorf("atomic fragment: got %d bytes, want the %d-byte packet", len(got), len(whole))
	}
	checkEmpty(t, r)
}

func TestReassembleDuplicate(t *testing.T) {
	r := &Reassembler{}
	whole := udp6(testSrc, testDst, 3000)
	fs := split(whole, 2, 1232)
	r.Add(fs[0])
	r.Add(fs[1])
	if r.Add(fs[1]) != nil {
		t.Fatal("a duplicate completed the datagram")
	}
	if got := r.Add(fs[2]); !bytes.Equal(got, whole) {
		t.Errorf("got %d bytes after a duplicate, want the %d-byte packet", len(got), len(whole))
	}
}

func TestReassembleOverlap(t *testing.T) {
	r := &Reassembler{Timeout: 50 * time.Millisecond}
	c := snapshot()
	whole := udp6(testSrc, testDst, 3000)
	r.Add(frag(whole, 3, 0, 1232))
	r.Add(frag(whole, 3, 1224, 2456)) // overlaps the first by 8 bytes
	if r.Add(frag(whole, 3, 2456, len(whole)-ipv6HeaderLen)) != nil {
		t.Error("completed a datagram with overlapping fragments")
	}
	// The second fragment as it should have been does not revive it either.
	if r.Add(frag(whole, 3, 1232, 2456)) != nil {
		t.Error("revived a dropped datagram")
	}
	if _, b := r.stats(); b != 0 {
		t.Errorf("dropped datagram still buffers %d bytes", b)
	}
	c.delta(t, map[*clientmetric.Metric]int64{metricReasmDropOverlap: 1})
	time.Sleep(200 * time.Millisecond)
	checkEmpty(t, r)
	c.delta(t, map[*clientmetric.Metric]int64{metricReasmDropOverlap: 1}) // the dropped slot's expiry is not a timeout
}

func TestReassembleInvalid(t *testing.T) {
	whole := udp6(testSrc, testDst, 3000)
	n := len(whole) - ipv6HeaderLen
	for _, tc := range []struct {
		name  string
		frags [][]byte
	}{
		{"two-last-fragments", [][]byte{frag(whole, 4, 0, 1232), frag(whole, 4, 2464, n), frag(whole[:len(whole)-8], 4, 1232, n-8)}},
		{"beyond-last", [][]byte{frag(whole[:len(whole)-1000], 4, 1232, n-1000), frag(whole, 4, 0, 1232), frag(whole, 4, 2464, n)}},
		{"not-multiple-of-8", [][]byte{frag(whole, 4, 0, 1230)}},
		{"udp-length", func() [][]byte {
			w := bytes.Clone(whole)
			binary.BigEndian.PutUint16(w[44:], 1000)
			return split(w, 4, 1232)
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Reassembler{}
			c := snapshot()
			for _, f := range tc.frags {
				if r.Add(f) != nil {
					t.Fatal("Add returned a packet")
				}
			}
			c.delta(t, map[*clientmetric.Metric]int64{metricReasmDropInvalid: 1})
		})
	}
}

func TestReassembleTimeout(t *testing.T) {
	r := &Reassembler{Timeout: 50 * time.Millisecond}
	c := snapshot()
	whole := udp6(testSrc, testDst, 3000)
	fs := split(whole, 5, 1232)
	r.Add(fs[0])
	r.Add(fs[1]) // the last is lost
	if n, b := r.stats(); n != 1 || b == 0 {
		t.Fatalf("pending %d with %d bytes; want 1 with some", n, b)
	}
	time.Sleep(200 * time.Millisecond) // no more fragments arrive: the timer frees it
	checkEmpty(t, r)
	c.delta(t, map[*clientmetric.Metric]int64{metricReasmTimeout: 1})
	// The late last fragment starts afresh and cannot complete.
	if r.Add(fs[2]) != nil {
		t.Error("the late last fragment completed an expired datagram")
	}
	time.Sleep(200 * time.Millisecond)
	checkEmpty(t, r)
	c.delta(t, map[*clientmetric.Metric]int64{metricReasmTimeout: 2})
}

func TestReassembleLimits(t *testing.T) {
	other := netip.MustParseAddr("fd7a:115c:a1e0::3")
	whole := udp6(testSrc, testDst, 3000)
	t.Run("per-source", func(t *testing.T) {
		r := &Reassembler{MaxPerSource: 2}
		c := snapshot()
		r.Add(frag(whole, 10, 0, 1232))
		r.Add(frag(whole, 11, 0, 1232))
		r.Add(frag(whole, 12, 0, 1232)) // refused
		c.delta(t, map[*clientmetric.Metric]int64{metricReasmDropLimit: 1})
		// Another source is not affected.
		w2 := udp6(other, testDst, 3000)
		var got []byte
		for _, f := range split(w2, 12, 1232) {
			got = r.Add(f)
		}
		if !bytes.Equal(got, w2) {
			t.Error("another source's datagram was not reassembled")
		}
		if n, _ := r.stats(); n != 2 {
			t.Errorf("%d pending; want 2", n)
		}
	})
	t.Run("pending", func(t *testing.T) {
		r := &Reassembler{MaxPending: 3}
		c := snapshot()
		for i := range 5 {
			src := netip.AddrFrom16([16]byte{0xfd, 15: byte(i)})
			r.Add(frag(udp6(src, testDst, 3000), 20, 0, 1232))
		}
		c.delta(t, map[*clientmetric.Metric]int64{metricReasmDropLimit: 2})
		if n, _ := r.stats(); n != 3 {
			t.Errorf("%d pending; want 3", n)
		}
	})
	t.Run("pending-expires", func(t *testing.T) {
		r := &Reassembler{MaxPending: 1, Timeout: 50 * time.Millisecond}
		r.Add(frag(whole, 21, 0, 1232))
		r.timer.Stop() // only the room check can expire it now
		time.Sleep(100 * time.Millisecond)
		var got []byte
		for _, f := range split(whole, 22, 1232) {
			got = r.Add(f)
		}
		if got == nil {
			t.Error("an overdue reassembly blocked a new one")
		}
	})
	t.Run("bytes", func(t *testing.T) {
		r := &Reassembler{MaxBytes: 5000}
		c := snapshot()
		r.Add(frag(whole, 30, 1232, 2464)) // 40+2464 bytes buffered
		r.Add(frag(whole, 31, 1232, 2464)) // over 5000: dropped
		c.delta(t, map[*clientmetric.Metric]int64{metricReasmDropLimit: 1})
		if _, b := r.stats(); b > 5000 {
			t.Errorf("%d bytes buffered, over MaxBytes", b)
		}
		// The first still completes.
		r.Add(frag(whole, 30, 0, 1232))
		if got := r.Add(frag(whole, 30, 2464, len(whole)-ipv6HeaderLen)); !bytes.Equal(got, whole) {
			t.Error("the datagram within the limit did not complete")
		}
	})
	t.Run("size", func(t *testing.T) {
		r := &Reassembler{MaxSize: 2000, Timeout: 50 * time.Millisecond}
		c := snapshot()
		var got []byte
		for _, f := range split(whole, 40, 1232) {
			got = r.Add(f)
		}
		if got != nil {
			t.Error("reassembled a datagram over MaxSize")
		}
		c.delta(t, map[*clientmetric.Metric]int64{metricReasmDropSize: 1})
		time.Sleep(200 * time.Millisecond)
		checkEmpty(t, r)
		small := udp6(testSrc, testDst, 1500)
		for _, f := range split(small, 41, 1232) {
			got = r.Add(f)
		}
		if !bytes.Equal(got, small) {
			t.Error("a datagram within MaxSize did not complete")
		}
	})
	t.Run("fragments", func(t *testing.T) {
		r := &Reassembler{}
		c := snapshot()
		big := udp6(testSrc, testDst, 1000)
		for _, f := range split(big, 50, 8) { // 127 fragments
			if r.Add(f) != nil {
				t.Fatal("reassembled a datagram of too many fragments")
			}
		}
		c.delta(t, map[*clientmetric.Metric]int64{metricReasmDropLimit: 1})
	})
}

func TestKernelReassembles(t *testing.T) {
	t.Cleanup(func() { SetKernelHandled(nil, true) })
	whole := udp6(testSrc, testDst, 2000)
	first, later := frag(whole, 1, 0, 1232), frag(whole, 1, 1232, 2008)
	tcp := bytes.Clone(first)
	tcp[40] = byte(ipproto.TCP)
	other := frag(udp6(testSrc, netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:7:a63:2"), 2000), 1, 0, 1232)

	SetKernelHandled([]netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:1790::/96")}, true)
	for _, tc := range []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"first", first, true},
		{"later", later, true},
		{"whole", whole, false},
		{"tcp-fragment", tcp, false},
		{"other-prefix", other, false},
		{"short", first[:47], false},
	} {
		if got := KernelReassembles(tc.pkt); got != tc.want {
			t.Errorf("%s: KernelReassembles = %v; want %v", tc.name, got, tc.want)
		}
	}
	SetKernelHandled([]netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:1790::/96")}, false)
	if KernelReassembles(first) {
		t.Error("KernelReassembles with UDP on netstack = true; want false")
	}
}
