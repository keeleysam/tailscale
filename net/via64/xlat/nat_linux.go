// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package xlat

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"tailscale.com/tsconst"
)

const natTable = "ts-via64"

type natOpts struct {
	netstackUDP    bool   // UDP is not DNATed, so netstack keeps it
	timeouts       bool   // the kernel has conntrack timeout policies
	flowsPerClient uint32 // new flows from a client address beyond this many concurrent ones are dropped
	splitUDP       bool   // UDP replies with DF over peerMTU get dfMark, so they reach the translator whole
}

// DefaultFlowsPerClient is the default cap on concurrent via64 flows from one client address. It is in the range of netstack's per-client cap on in-flight dials (5461 on Linux), which bounds a client there, and leaves room for nf_conntrack_max: each flow uses two entries.
const DefaultFlowsPerClient = 4096

// clientsSet is the dynamic set that counts each client address's flows.
const clientsSet = "via64-clients"

/*
installNAT replaces the rules in via64's two nftables tables in one transaction. It keeps existing tables and timeout objects: deleting an object detaches it from the flows using it, which would cut open UDP flows to conntrack's 30-second default whenever the routes change.

IPv6 prerouting DNATs the advertised via prefixes into Canonical, keeping the low 32 bits; postrouting NAT66s clients to X6 on the way into the pair, and IPv4 postrouting masquerades X4 onto the LAN. Both source NATs run just before srcnat, ahead of linuxfw's subnet-route masquerade, which would match the same packets.
*/
func installNAT(ingress string, prefixes []netip.Prefix, x Xlat, o natOpts) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	if err := forEachNATTable(c, c.FlushTable); err != nil {
		return err
	}
	srcnat := nftables.ChainPriorityRef(*nftables.ChainPriorityNATSource - 1)
	canonMin := Canonical.Addr().As16()
	canonMax := canonMin
	for i := 12; i < 16; i++ {
		canonMax[i] = 0xff
	}
	x6 := x.X6().As16()

	t6 := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv6, Name: natTable})
	// Only the DNAT may address Canonical, and translated replies arriving on the primary: anything else would bypass the site's grants and the 4via6 target policy.
	guard6 := c.AddChain(&nftables.Chain{Name: "guard", Table: t6, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityRaw})
	c.AddRule(&nftables.Rule{Table: t6, Chain: guard6, Exprs: slices.Concat(
		matchIfname(expr.MetaKeyIIFNAME, PrimaryName, expr.CmpOpNeq),
		matchPrefix(Canonical, 24, 16), // ip6 daddr
		[]expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}},
	)})
	if o.timeouts {
		addTimeouts(c, t6, unix.NFPROTO_IPV6, !o.netstackUDP)
		timeouts6 := c.AddChain(&nftables.Chain{Name: "timeouts", Table: t6, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityMangle})
		for _, p := range prefixes {
			addTimeoutRules(c, t6, timeouts6, slices.Concat(matchIfname(expr.MetaKeyIIFNAME, ingress, expr.CmpOpEq), matchPrefix(p, 24, 16)), !o.netstackUDP)
		}
	}
	var notUDP []expr.Any
	if o.netstackUDP {
		notUDP = []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
		}
	}
	pre6 := c.AddChain(&nftables.Chain{Name: "prerouting", Table: t6, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest})
	for _, p := range prefixes {
		c.AddRule(&nftables.Rule{Table: t6, Chain: pre6, Exprs: slices.Concat(
			matchIfname(expr.MetaKeyIIFNAME, ingress, expr.CmpOpEq),
			matchPrefix(p, 24, 16), // ip6 daddr
			notUDP,
			[]expr.Any{
				&expr.Immediate{Register: 1, Data: canonMin[:]},
				&expr.Immediate{Register: 2, Data: canonMax[:]},
				// Prefix: keep the bits where min and max differ, take the rest from min.
				&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV6, RegAddrMin: 1, RegAddrMax: 2, Prefix: true},
			},
		)})
	}
	// While a steering rule or route is missing, DNATed packets would leave by another route and conntrack would keep them without NAT66, breaking the flow after the repair. Dropped here, they are retransmitted instead.
	fwd6 := c.AddChain(&nftables.Chain{Name: "forward", Table: t6, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter})
	c.AddRule(&nftables.Rule{Table: t6, Chain: fwd6, Exprs: slices.Concat(
		matchPrefix(Canonical, 24, 16), // ip6 daddr
		matchIfname(expr.MetaKeyOIFNAME, PrimaryName, expr.CmpOpNeq),
		[]expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}},
	)})
	/*
		A packet from the tailnet that is still addressed to a via prefix here was not DNATed, because conntrack marked it invalid (out of window, a SYN-ACK or bare ACK with no flow, a bad checksum). Left alone, table 52 routes it back out the tun device into netstack's outbound 4via6 intercept, which answers with a RST that can kill the client's live connection. Drop it instead: the kernel path owns these prefixes while it is on.
	*/
	for _, p := range prefixes {
		c.AddRule(&nftables.Rule{Table: t6, Chain: fwd6, Exprs: slices.Concat(
			matchIfname(expr.MetaKeyIIFNAME, ingress, expr.CmpOpEq),
			matchPrefix(p, 24, 16), // ip6 daddr
			[]expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}},
		)})
	}
	// Replies from the pair that conntrack cannot match skip the reverse NAT66 and would leave with X6 or Canonical addresses.
	c.AddRule(&nftables.Rule{Table: t6, Chain: fwd6, Exprs: slices.Concat(
		matchIfname(expr.MetaKeyIIFNAME, PrimaryName, expr.CmpOpEq),
		matchCtState(expr.CtStateBitINVALID),
		[]expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}},
	)})
	/*
		tailscaled's filter accepts every TCP segment without SYN, leaving those to netstack, which drops them for connections it does not have. Conntrack instead picks a mid-stream segment up as a new flow (nf_conntrack_tcp_loose), so a bare ACK would reach any host and port in the site, whatever the grants. Only a SYN may start a via64 flow; dropping the packet also discards its unconfirmed conntrack entry.
	*/
	fromClient := slices.Concat(
		matchIfname(expr.MetaKeyIIFNAME, ingress, expr.CmpOpEq),
		matchPrefix(Canonical, 24, 16), // ip6 daddr: DNATed by via64
		matchCtState(expr.CtStateBitNEW),
	)
	c.AddRule(&nftables.Rule{Table: t6, Chain: fwd6, Exprs: slices.Concat(
		fromClient,
		[]expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1}, // tcp flags
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{tcpFIN | tcpSYN | tcpRST | tcpACK}, Xor: []byte{0}},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{tcpSYN}},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	)})
	// Netstack caps each client's in-flight dials; without a cap here, one client could fill the conntrack table for every flow the router forwards. Each element counts its address's live flows and is garbage-collected when the count reaches zero.
	clients := &nftables.Set{Table: t6, Name: clientsSet, KeyType: nftables.TypeIP6Addr, Dynamic: true, Size: 65535}
	if err := c.AddSet(clients, nil); err != nil {
		return err
	}
	c.AddRule(&nftables.Rule{Table: t6, Chain: fwd6, Exprs: slices.Concat(
		fromClient,
		[]expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16}, // ip6 saddr
			&expr.Dynset{SrcRegKey: 1, SetName: clients.Name, SetID: clients.ID, Operation: uint32(unix.NFT_DYNSET_OP_ADD), Exprs: []expr.Any{
				&expr.Connlimit{Count: o.flowsPerClient, Flags: expr.NFT_CONNLIMIT_F_INV}, // ct count over
			}},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	)})
	post6 := c.AddChain(&nftables.Chain{Name: "postrouting", Table: t6, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookPostrouting, Priority: srcnat})
	c.AddRule(&nftables.Rule{Table: t6, Chain: post6, Exprs: slices.Concat(
		matchIfname(expr.MetaKeyOIFNAME, PrimaryName, expr.CmpOpEq),
		matchCtStatus(ipsDstNAT), // only flows the canonical DNAT produced
		[]expr.Any{
			&expr.Immediate{Register: 1, Data: x6[:]},
			&expr.NAT{Type: expr.NATTypeSourceNAT, Family: unix.NFPROTO_IPV6, RegAddrMin: 1},
		},
	)})
	t4 := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: natTable})
	// Only the translator sends from X4, out of the peer. Anything else from X4 would be masqueraded below and reach the tailnet as the router.
	guard4 := c.AddChain(&nftables.Chain{Name: "guard", Table: t4, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityRaw})
	c.AddRule(&nftables.Rule{Table: t4, Chain: guard4, Exprs: slices.Concat(
		matchIfname(expr.MetaKeyIIFNAME, PeerName, expr.CmpOpNeq),
		matchPrefix(netip.PrefixFrom(x.X4, 32), 12, 4), // ip saddr
		[]expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}},
	)})
	if o.timeouts {
		addTimeouts(c, t4, unix.NFPROTO_IPV4, !o.netstackUDP)
	}
	// Give replies to X4 linuxfw's subnet-route mark, so a forward drop policy (Docker's) lets them through as it does tailscale0's traffic. This runs after conntrack has restored X4.
	mark4 := c.AddChain(&nftables.Chain{Name: "mark", Table: t4, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityFilter})
	c.AddRule(&nftables.Rule{Table: t4, Chain: mark4, Exprs: slices.Concat(
		matchPrefix(netip.PrefixFrom(x.X4, 32), 16, 4), // ip daddr
		[]expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(^uint32(tsconst.LinuxFwmarkMaskNum)), Xor: u32(tsconst.LinuxSubnetRouteMarkNum)},
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
		},
	)})
	// Mark replies without DF that are too large to pass whole, so markRule routes them with fragMTU; everything else keeps peerMTU.
	c.AddRule(&nftables.Rule{Table: t4, Chain: mark4, Exprs: slices.Concat(
		matchPrefix(netip.PrefixFrom(x.X4, 32), 16, 4), // ip daddr
		[]expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 6, Len: 2}, // ip frag-off
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 2, Mask: []byte{0x40, 0}, Xor: []byte{0, 0}},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 0}},                                // no DF
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 2, Len: 2},      // ip length
			&expr.Cmp{Op: expr.CmpOpGt, Register: 1, Data: binary.BigEndian.AppendUint16(nil, peerMTU)}, // too large to pass whole
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(^uint32(fragMark)), Xor: u32(fragMark)},
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
		},
	)})
	if o.splitUDP && !o.netstackUDP {
		// Mark UDP replies with DF (and not fragments) that are too large to pass whole, so a rule routes them to the translator with dfMTU, which splits them into IPv6 fragments.
		c.AddRule(&nftables.Rule{Table: t4, Chain: mark4, Exprs: slices.Concat(
			matchPrefix(netip.PrefixFrom(x.X4, 32), 16, 4), // ip daddr
			[]expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1}, // ip protocol
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 6, Len: 2}, // ip frag-off
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x40, 0}},                        // DF, offset 0, no MF
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 2, Len: 2}, // ip length
				&expr.Cmp{Op: expr.CmpOpGt, Register: 1, Data: binary.BigEndian.AppendUint16(nil, peerMTU)},
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(^uint32(dfMark)), Xor: u32(dfMark)},
				&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
			},
		)})
	}
	// The IPv4 leg's own conntrack can still call a packet invalid. Without its NAT entry it would reach the LAN from X4 rather than the router's address.
	fwd4 := c.AddChain(&nftables.Chain{Name: "forward", Table: t4, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter})
	c.AddRule(&nftables.Rule{Table: t4, Chain: fwd4, Exprs: slices.Concat(
		matchIfname(expr.MetaKeyIIFNAME, PeerName, expr.CmpOpEq),
		matchCtState(expr.CtStateBitINVALID),
		[]expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}},
	)})
	if o.timeouts {
		timeouts4 := c.AddChain(&nftables.Chain{Name: "timeouts", Table: t4, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityMangle})
		addTimeoutRules(c, t4, timeouts4, matchIfname(expr.MetaKeyIIFNAME, PeerName, expr.CmpOpEq), !o.netstackUDP)
	}
	post4 := c.AddChain(&nftables.Chain{Name: "postrouting", Table: t4, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookPostrouting, Priority: srcnat})
	c.AddRule(&nftables.Rule{Table: t4, Chain: post4, Exprs: slices.Concat(
		matchPrefix(netip.PrefixFrom(x.X4, 32), 12, 4), // ip saddr
		matchIfname(expr.MetaKeyOIFNAME, PeerName, expr.CmpOpNeq),
		[]expr.Any{&expr.Masq{}},
	)})
	return c.Flush()
}

const (
	udpTimeout = "via64-udp"
	dnsTimeout = "via64-dns"
	tcpTimeout = "via64-tcp"
)

// addTimeouts adds the timeout policies: tcpTimeoutPolicy, and with udp netstack's UDP idle timeouts (2 minutes, 30 seconds for DNS).
func addTimeouts(c *nftables.Conn, t *nftables.Table, l3 uint16, udp bool) {
	c.AddObj(&nftables.NamedObj{Table: t, Name: tcpTimeout, Type: nftables.ObjTypeCtTimeout, Obj: &expr.CtTimeout{
		L3Proto: l3,
		L4Proto: unix.IPPROTO_TCP,
		Policy:  tcpTimeoutPolicy(),
	}})
	if !udp {
		return
	}
	for name, secs := range map[string]uint32{udpTimeout: 120, dnsTimeout: 30} {
		c.AddObj(&nftables.NamedObj{Table: t, Name: name, Type: nftables.ObjTypeCtTimeout, Obj: &expr.CtTimeout{
			L3Proto: l3,
			L4Proto: unix.IPPROTO_UDP,
			Policy:  expr.CtStatePolicyTimeout{expr.CtStateUDPUNREPLIED: secs, expr.CtStateUDPREPLIED: secs},
		}})
	}
}

/*
establishedTimeout caps the idle timeout of established via64 TCP flows, in seconds. The kernel's default is 5 days, and each via64 flow holds two conntrack entries, so flows orphaned by clients that sleep or roam without a FIN or RST would pile up for days. Netstack reaps those with TCP keepalive after about 2 hours 11 minutes (2 h idle, then 9 probes 75 s apart).

The kernel path cannot send keepalives, so an idle flow that nobody probes is cut at this timeout. 4 hours is twice the 2-hour keepalive idle time that Linux, macOS and Windows use by default, so connections with SO_KEEPALIVE at either end survive any idle period, and connections without it get 4 idle hours.
*/
const establishedTimeout = 4 * 60 * 60

// tcpTimeoutPolicy returns the kernel's TCP timeouts from its sysctls, with the established timeout capped at establishedTimeout. Every state is set because google/nftables fills in missing ones with its own defaults.
func tcpTimeoutPolicy() expr.CtStatePolicyTimeout {
	get := func(name string, def uint32) uint32 {
		v, err := strconv.ParseUint(readSysctl("net/netfilter/nf_conntrack_tcp_timeout_"+name), 10, 32)
		if err != nil {
			return def
		}
		return uint32(v)
	}
	return expr.CtStatePolicyTimeout{
		expr.CtStateTCPSYNSENT:     get("syn_sent", 120),
		expr.CtStateTCPSYNRECV:     get("syn_recv", 60),
		expr.CtStateTCPESTABLISHED: min(get("established", 432000), establishedTimeout),
		expr.CtStateTCPFINWAIT:     get("fin_wait", 120),
		expr.CtStateTCPCLOSEWAIT:   get("close_wait", 60),
		expr.CtStateTCPLASTACK:     get("last_ack", 30),
		expr.CtStateTCPTIMEWAIT:    get("time_wait", 120),
		expr.CtStateTCPCLOSE:       get("close", 10),
		expr.CtStateTCPSYNSENT2:    get("syn_sent", 120),
		expr.CtStateTCPRETRANS:     get("max_retrans", 300),
		expr.CtStateTCPUNACK:       get("unacknowledged", 300),
	}
}

// addTimeoutRules attaches the policies to new flows matching base. They run at mangle priority: the kernel applies a policy only to an unconfirmed entry, which does not exist yet at raw priority.
func addTimeoutRules(c *nftables.Conn, t *nftables.Table, ch *nftables.Chain, base []expr.Any, udp bool) {
	c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: slices.Concat(base, []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Objref{Type: int(nftables.ObjTypeCtTimeout), Name: tcpTimeout},
	})})
	if !udp {
		return
	}
	for _, r := range []struct {
		op   expr.CmpOp
		name string
	}{{expr.CmpOpEq, dnsTimeout}, {expr.CmpOpNeq, udpTimeout}} {
		c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: slices.Concat(base, []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, // udp dport
			&expr.Cmp{Op: r.op, Register: 1, Data: []byte{0, 53}},
			&expr.Objref{Type: int(nftables.ObjTypeCtTimeout), Name: r.name},
		})})
	}
}

// Replaced in tests.
var ctTimeoutSupportedFunc = ctTimeoutSupported

// ctTimeoutSupported adds a timeout object in a scratch table and removes it again.
func ctTimeoutSupported() bool {
	c, err := nftables.New()
	if err != nil {
		return true // not the kernel's missing feature; let the real error show
	}
	t := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv6, Name: natTable + "-probe"})
	addTimeouts(c, t, unix.NFPROTO_IPV6, true)
	err = c.Flush()
	if err == nil {
		c.DelTable(t)
		c.Flush()
	}
	return !errors.Is(err, unix.ENOENT)
}

// firewalldRunning reports whether firewalld's nftables table exists.
func firewalldRunning() bool {
	c, err := nftables.New()
	if err != nil {
		return false
	}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	return err == nil && slices.ContainsFunc(tables, func(t *nftables.Table) bool { return t.Name == "firewalld" })
}

// forwardDropChain returns the first forward chain with a drop policy outside the ip and ip6 filter tables' FORWARD chains, where linuxfw's accepts and Docker's drop policy are, as "family table chain".
func forwardDropChain() string {
	c, err := nftables.New()
	if err != nil {
		return ""
	}
	chains, err := c.ListChains()
	if err != nil {
		return ""
	}
	for _, ch := range chains {
		if ch.Hooknum == nil || *ch.Hooknum != *nftables.ChainHookForward || ch.Policy == nil || *ch.Policy != nftables.ChainPolicyDrop {
			continue
		}
		fam, ok := map[nftables.TableFamily]string{nftables.TableFamilyIPv4: "ip", nftables.TableFamilyIPv6: "ip6", nftables.TableFamilyINet: "inet"}[ch.Table.Family]
		if !ok {
			continue // bridge chains see bridged frames, not routed packets
		}
		if (fam == "ip" || fam == "ip6") && ch.Table.Name == "filter" && ch.Name == "FORWARD" {
			continue
		}
		return fam + " " + ch.Table.Name + " " + ch.Name
	}
	return ""
}

func natPresent() (bool, error) {
	c, err := nftables.New()
	if err != nil {
		return false, err
	}
	for _, fam := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6} {
		tables, err := c.ListTablesOfFamily(fam)
		if err != nil {
			return false, err
		}
		if !slices.ContainsFunc(tables, func(t *nftables.Table) bool { return t.Name == natTable }) {
			return false, nil
		}
	}
	return true, nil
}

// deleteNAT removes the via64 tables if they exist.
func deleteNAT() error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	if err := forEachNATTable(c, c.DelTable); err != nil {
		return err
	}
	return c.Flush()
}

// forEachNATTable queues fn for each via64 table that exists, in either family.
func forEachNATTable(c *nftables.Conn, fn func(*nftables.Table)) error {
	for _, fam := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6} {
		tables, err := c.ListTablesOfFamily(fam)
		if err != nil {
			return err
		}
		for _, t := range tables {
			if t.Name == natTable {
				fn(t)
			}
		}
	}
	return nil
}

// ipsDstNAT is IPS_DST_NAT from include/uapi/linux/netfilter/nf_conntrack_common.h.
const ipsDstNAT = 1 << 5

// matchCtStatus matches connections whose conntrack status has any of bits set.
func matchCtStatus(bits uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATUS},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(bits), Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
	}
}

// TCP header flag bits.
const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

// matchCtState matches packets whose conntrack state is any of bits (expr.CtStateBit*).
func matchCtState(bits uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: u32(bits), Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
	}
}

// u32 encodes v in host byte order, as nftables registers hold marks and conntrack status.
func u32(v uint32) []byte {
	return binary.NativeEndian.AppendUint32(nil, v)
}

func matchIfname(key expr.MetaKey, dev string, op expr.CmpOp) []expr.Any {
	name := make([]byte, unix.IFNAMSIZ)
	copy(name, dev)
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: op, Register: 1, Data: name},
	}
}

// matchPrefix matches the n-byte address at offset in the network header against p.
func matchPrefix(p netip.Prefix, offset, n uint32) []expr.Any {
	p = p.Masked()
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: n},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: n, Mask: net.CIDRMask(p.Bits(), int(n)*8), Xor: make([]byte, n)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: p.Addr().AsSlice()},
	}
}
