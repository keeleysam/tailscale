// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package via64

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"tailscale.com/types/ipproto"
	"tailscale.com/util/clientmetric"
)

/*
KernelReassembles reports whether pkt is an IPv6 fragment of a UDP datagram to a via address whose UDP the kernel translates. tailscaled reassembles those (Reassembler) and hands the kernel the whole datagram.

Passed on one by one, the fragments would reach the IPv4 host as IPv4 fragments: the kernel reassembles them for conntrack, but forwarding fragments them again at the largest fragment's size, and the translator has no way to reassemble. Some hosts reject IPv4 fragments: Cloudflare answers a QUIC path MTU probe that arrives fragmented with ICMP "port unreachable", which fails the client's connection. Netstack, as the endpoint of the flow, sends the whole datagram from its own socket instead.

Only fragments that follow the IPv6 header directly are recognised, as net/packet parses no other extension headers. The Fragment Header's Next Header is the same in every fragment of a datagram, so later fragments are recognised too.
*/
func KernelReassembles(pkt []byte) bool {
	if len(pkt) < ipv6HeaderLen+fragHeaderLen || pkt[0]>>4 != 6 || pkt[6] != fragHeaderProto || pkt[ipv6HeaderLen] != byte(ipproto.UDP) {
		return false
	}
	return KernelHandles(netip.AddrFrom16([16]byte(pkt[24:40])), ipproto.UDP)
}

const (
	ipv6HeaderLen   = 40
	fragHeaderLen   = 8
	fragHeaderProto = 44
	udpHeaderLen    = 8

	// DefaultReasmTimeout is how long a Reassembler waits for a datagram's missing fragments. RFC 8200 allows 60 seconds; a lost fragment would wedge its datagram's slot that long, and a client resends sooner than that.
	DefaultReasmTimeout = 5 * time.Second
	// DefaultReasmMaxSize is the largest reassembled IPv6 packet, its header included. It is also the most an IPv6 packet's Payload Length allows, and translates to at most 65515 bytes of IPv4.
	DefaultReasmMaxSize = 65535
	// DefaultReasmPerSource caps one source address's concurrent reassemblies.
	DefaultReasmPerSource = 16
	// DefaultReasmPending caps the concurrent reassemblies of all sources.
	DefaultReasmPending = 256
	// DefaultReasmBytes caps the bytes buffered for incomplete datagrams, like the kernel's ip6frag_high_thresh (4 MiB).
	DefaultReasmBytes = 4 << 20

	// reasmMaxFrags caps a datagram's fragments: enough for the largest datagram in the 1232-byte fragments of a 1280-byte MTU, so that tiny fragments cannot make the overlap checks quadratic.
	reasmMaxFrags = 64
)

var (
	metricReasmOK           = clientmetric.NewCounter("via64_reasm_ok")
	metricReasmTimeout      = clientmetric.NewCounter("via64_reasm_timeout")
	metricReasmDropOverlap  = clientmetric.NewCounter("via64_reasm_drop_overlap")
	metricReasmDropInvalid  = clientmetric.NewCounter("via64_reasm_drop_invalid")
	metricReasmDropSize     = clientmetric.NewCounter("via64_reasm_drop_size")
	metricReasmDropLimit    = clientmetric.NewCounter("via64_reasm_drop_limit")
	metricReasmDropFiltered = clientmetric.NewCounter("via64_reasm_drop_filter")
	metricReasmDropError    = clientmetric.NewCounter("via64_reasm_drop_error")
)

// CountReasmFiltered counts a reassembled datagram the packet filter dropped.
func CountReasmFiltered() { metricReasmDropFiltered.Add(1) }

// CountReasmError counts a reassembled datagram that could not be handed to the kernel.
func CountReasmError() { metricReasmDropError.Add(1) }

/*
Reassembler reassembles IPv6 fragments of UDP datagrams (RFC 8200 section 4.5) for the kernel 4via6 path; see KernelReassembles. It is bounded: a datagram that is not complete within Timeout is dropped, and so is one that would exceed MaxSize, or a new one over MaxPerSource or MaxPending reassemblies or MaxBytes buffered. A fragment that overlaps another of its datagram, or whose length or offset is inconsistent with the others, drops the whole datagram; an exact duplicate is ignored, as Linux does (RFC 5722 errata 3089).

A dropped datagram's slot stays until its timeout, so that its other fragments are dropped too instead of starting a reassembly that cannot complete.

The zero value uses the defaults. It is safe for concurrent use.
*/
type Reassembler struct {
	Timeout      time.Duration // zero means DefaultReasmTimeout
	MaxSize      int           // zero means DefaultReasmMaxSize; at most 65535
	MaxPerSource int           // zero means DefaultReasmPerSource
	MaxPending   int           // zero means DefaultReasmPending
	MaxBytes     int           // zero means DefaultReasmBytes
	Headroom     int           // free bytes before the packet in the buffers Add returns

	mu      sync.Mutex
	pending map[fragKey]*reasm
	perSrc  map[[16]byte]int
	bytes   int // cap of all pending buffers
	timer   *time.Timer
	armed   bool
}

type fragKey struct {
	src, dst [16]byte
	id       uint32
}

type fragRange struct{ off, end int }

type reasm struct {
	key      fragKey
	deadline time.Time
	buf      []byte // Headroom bytes, the first fragment's IPv6 header, then the fragmentable part at its offsets
	ranges   []fragRange
	have     int  // fragmentable bytes received
	maxEnd   int  // the furthest end of a received fragment
	total    int  // the fragmentable part's length, once the last fragment is in; else -1
	nh       byte // the Fragment Header's Next Header
	first    bool // the first fragment is in
	dead     bool // dropped; absorbs the datagram's other fragments until the deadline
}

func orDefault[T int | time.Duration](v, def T) T {
	if v <= 0 {
		return def
	}
	return v
}

/*
Add takes an IPv6 packet whose IPv6 header is followed by a Fragment Header, and returns the reassembled IPv6 packet, after Headroom free bytes, once pkt completes its datagram; otherwise nil. It does not keep pkt.

The reassembled packet has the first fragment's IPv6 header with the Fragment Header removed, as RFC 8200 section 4.5 says. An atomic fragment (offset 0, no more fragments) is returned at once without its Fragment Header (RFC 6946).
*/
func (r *Reassembler) Add(pkt []byte) []byte {
	if len(pkt) < ipv6HeaderLen+fragHeaderLen || pkt[0]>>4 != 6 || pkt[6] != fragHeaderProto {
		metricReasmDropInvalid.Add(1)
		return nil
	}
	plen := int(binary.BigEndian.Uint16(pkt[4:6]))
	if plen < fragHeaderLen || ipv6HeaderLen+plen > len(pkt) {
		metricReasmDropInvalid.Add(1)
		return nil
	}
	pkt = pkt[:ipv6HeaderLen+plen]
	fh := pkt[ipv6HeaderLen : ipv6HeaderLen+fragHeaderLen]
	offlg := binary.BigEndian.Uint16(fh[2:4])
	off, more := int(offlg&^7), offlg&1 != 0
	data := pkt[ipv6HeaderLen+fragHeaderLen:]
	end := off + len(data)
	headroom := max(r.Headroom, 0)
	maxSize := min(orDefault(r.MaxSize, DefaultReasmMaxSize), 65535)

	if off == 0 && !more {
		if ipv6HeaderLen+end > maxSize {
			metricReasmDropSize.Add(1)
			return nil
		}
		out := make([]byte, headroom+ipv6HeaderLen+len(data))
		copy(out[headroom:], pkt[:ipv6HeaderLen])
		copy(out[headroom+ipv6HeaderLen:], data)
		return r.finish(out, headroom, fh[0])
	}
	// RFC 8200: all but the last fragment carry a multiple of 8 bytes.
	if len(data) == 0 || more && len(data)%8 != 0 {
		metricReasmDropInvalid.Add(1)
		return nil
	}

	key := fragKey{src: [16]byte(pkt[8:24]), dst: [16]byte(pkt[24:40]), id: binary.BigEndian.Uint32(fh[4:8])}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.pending[key]
	if p == nil {
		if !r.roomLocked(key.src, now) {
			metricReasmDropLimit.Add(1)
			return nil
		}
		p = &reasm{key: key, deadline: now.Add(orDefault(r.Timeout, DefaultReasmTimeout)), total: -1, nh: fh[0]}
		r.pending[key] = p
		r.perSrc[key.src]++
		r.armLocked()
	}
	if p.dead {
		return nil
	}
	if ipv6HeaderLen+end > maxSize {
		r.killLocked(p)
		metricReasmDropSize.Add(1)
		return nil
	}
	if fh[0] != p.nh || p.total >= 0 && end > p.total || !more && (p.total >= 0 && end != p.total || end < p.maxEnd) {
		r.killLocked(p)
		metricReasmDropInvalid.Add(1)
		return nil
	}
	for _, g := range p.ranges {
		if g.off == off && g.end == end {
			return nil // a duplicate
		}
		if off < g.end && g.off < end {
			r.killLocked(p)
			metricReasmDropOverlap.Add(1)
			return nil
		}
	}
	if len(p.ranges) == reasmMaxFrags {
		r.killLocked(p)
		metricReasmDropLimit.Add(1)
		return nil
	}
	if need := headroom + ipv6HeaderLen + end; need > len(p.buf) {
		if need > cap(p.buf) {
			// Grow by doubling, so a datagram arriving in order is copied a few times, not once per fragment; but never past the datagram's known size or maxSize.
			limit := headroom + maxSize
			if p.total >= 0 || !more {
				limit = headroom + ipv6HeaderLen + max(p.total, end)
			}
			c := max(need, min(2*cap(p.buf), limit))
			maxBytes := orDefault(r.MaxBytes, DefaultReasmBytes)
			if r.bytes+c-cap(p.buf) > maxBytes {
				c = need
			}
			if r.bytes+c-cap(p.buf) > maxBytes {
				r.killLocked(p)
				metricReasmDropLimit.Add(1)
				return nil
			}
			nb := make([]byte, need, c)
			copy(nb, p.buf)
			r.bytes += c - cap(p.buf)
			p.buf = nb
		} else {
			p.buf = p.buf[:need]
		}
	}
	copy(p.buf[headroom+ipv6HeaderLen+off:], data)
	if off == 0 {
		copy(p.buf[headroom:], pkt[:ipv6HeaderLen])
		p.first = true
	}
	if !more {
		p.total = end
	}
	p.ranges = append(p.ranges, fragRange{off, end})
	p.have += len(data)
	p.maxEnd = max(p.maxEnd, end)
	if !p.first || p.total < 0 || p.have != p.total {
		return nil
	}
	out := p.buf[:headroom+ipv6HeaderLen+p.total]
	r.removeLocked(p)
	return r.finish(out, headroom, p.nh)
}

// finish turns out (after headroom) into the reassembled packet with next header nh, checking the UDP length covers it exactly.
func (r *Reassembler) finish(out []byte, headroom int, nh byte) []byte {
	pkt := out[headroom:]
	payload := len(pkt) - ipv6HeaderLen
	if nh != byte(ipproto.UDP) || payload < udpHeaderLen || int(binary.BigEndian.Uint16(pkt[ipv6HeaderLen+4:])) != payload {
		metricReasmDropInvalid.Add(1)
		return nil
	}
	pkt[6] = nh
	binary.BigEndian.PutUint16(pkt[4:6], uint16(payload))
	metricReasmOK.Add(1)
	return out
}

// roomLocked reports whether src may start another reassembly, expiring overdue ones first if it is at a limit.
func (r *Reassembler) roomLocked(src [16]byte, now time.Time) bool {
	if r.pending == nil {
		r.pending = map[fragKey]*reasm{}
		r.perSrc = map[[16]byte]int{}
	}
	full := func() bool {
		return len(r.pending) >= orDefault(r.MaxPending, DefaultReasmPending) || r.perSrc[src] >= orDefault(r.MaxPerSource, DefaultReasmPerSource)
	}
	if full() {
		r.expireLocked(now)
	}
	return !full()
}

// killLocked drops p's datagram, keeping its slot until the deadline.
func (r *Reassembler) killLocked(p *reasm) {
	r.bytes -= cap(p.buf)
	p.buf, p.ranges, p.dead = nil, nil, true
}

func (r *Reassembler) removeLocked(p *reasm) {
	r.bytes -= cap(p.buf)
	p.buf = nil
	delete(r.pending, p.key)
	if r.perSrc[p.key.src]--; r.perSrc[p.key.src] <= 0 {
		delete(r.perSrc, p.key.src)
	}
}

func (r *Reassembler) expireLocked(now time.Time) {
	for _, p := range r.pending {
		if now.Before(p.deadline) {
			continue
		}
		if !p.dead {
			metricReasmTimeout.Add(1)
		}
		r.removeLocked(p)
	}
}

// armLocked makes sure the timer that expires overdue reassemblies is running, so a lost fragment's datagram is freed even if no other fragment arrives.
func (r *Reassembler) armLocked() {
	if r.armed {
		return
	}
	r.armed = true
	d := orDefault(r.Timeout, DefaultReasmTimeout)
	if r.timer == nil {
		r.timer = time.AfterFunc(d, r.expire)
	} else {
		r.timer.Reset(d)
	}
}

func (r *Reassembler) expire() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	r.expireLocked(now)
	r.armed = false
	if len(r.pending) == 0 {
		return
	}
	next := now.Add(orDefault(r.Timeout, DefaultReasmTimeout))
	for _, p := range r.pending {
		if p.deadline.Before(next) {
			next = p.deadline
		}
	}
	r.armed = true
	r.timer.Reset(max(next.Sub(now), time.Millisecond))
}

// stats returns the number of pending reassemblies and the bytes they buffer, for tests.
func (r *Reassembler) stats() (pending, bytes int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending), r.bytes
}
