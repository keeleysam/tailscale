// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package policydoc

import "testing"

func TestEntriesWellFormed(t *testing.T) {
	if len(Entries) == 0 {
		t.Fatal("Entries is empty")
	}
	knownCategories := map[string]bool{
		CategoryAutoUpdate:   true,
		CategoryExitNode:     true,
		CategoryOrganization: true,
		CategoryRuntime:      true,
		CategoryUIVisibility: true,
	}
	seen := make(map[string]bool, len(Entries))
	for _, e := range Entries {
		if e.Key == "" {
			t.Error("found an Entry with an empty Key")
			continue
		}
		if seen[string(e.Key)] {
			t.Errorf("duplicate policydoc.Entry for key %q", e.Key)
		}
		seen[string(e.Key)] = true
		if e.Label == "" {
			t.Errorf("policydoc.Entry for %q has an empty Label", e.Key)
		}
		if e.Description == "" {
			t.Errorf("policydoc.Entry for %q has an empty Description", e.Key)
		}
		if !knownCategories[e.Category] {
			t.Errorf("policydoc.Entry for %q has unknown Category %q", e.Key, e.Category)
		}
	}
}
