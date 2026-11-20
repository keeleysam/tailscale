// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package xlat

// Pair is the netkit pair: client packets leave the stack on PrimaryName and come back in on PeerName as IPv4, and replies go the other way.
type Pair struct {
	PrimaryIndex, PeerIndex int
}

// Backend attaches the translator to the pair. It is an interface so that this package need not import the BPF objects, and tests can stub it.
type Backend interface {
	Install(p Pair, x Xlat) error
	// Attached reports whether the translator is still attached to both of the pair's devices.
	Attached(p Pair) bool
	// Counters returns the translator's packet counters since Install, by name.
	Counters() (map[string]uint64, error)
	Close() error
}
