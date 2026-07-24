// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import (
	"testing"

	"tailscale.com/util/syspolicy/policydoc"
	"tailscale.com/util/syspolicy/setting"
)

func TestPolicydocCoversAllDefinitions(t *testing.T) {
	registerWellKnownSettingsForTest(t)
	defs, err := setting.Definitions()
	if err != nil {
		t.Fatalf("setting.Definitions() error: %v", err)
	}
	byKey := make(map[string]policydoc.Entry, len(policydoc.Entries))
	for _, e := range policydoc.Entries {
		byKey[string(e.Key)] = e
	}
	for _, d := range defs {
		if _, ok := byKey[string(d.Key())]; !ok {
			t.Errorf("no policydoc.Entry for registered key %q; add one to util/syspolicy/policydoc", d.Key())
		}
	}
}
