// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"net"
	"testing"
)

func TestIsProblematicInterfaceVia64(t *testing.T) {
	for _, tt := range []struct {
		name string
		want bool
	}{
		{"tsvia0", true},
		{"tsvia1", true},
		{"tsvia2", false},
		{"eth0", false},
		{"zt0", true},
	} {
		if got := isProblematicInterface(&net.Interface{Name: tt.name}); got != tt.want {
			t.Errorf("isProblematicInterface(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
