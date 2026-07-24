// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"testing"

	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policydoc"
	"tailscale.com/util/syspolicy/setting"
)

func TestLoadPolicies(t *testing.T) {
	if err := setting.SetDefinitionsForTest(t,
		setting.NewDefinition(pkey.ControlURL, setting.DeviceSetting, setting.StringValue),
		setting.NewDefinition(pkey.AlwaysOn, setting.DeviceSetting, setting.BooleanValue),
		setting.NewDefinition(pkey.DeviceSerialNumber, setting.DeviceSetting, setting.StringValue, "android", "iOS", "tvOS"),
	); err != nil {
		t.Fatalf("SetDefinitionsForTest failed: %v", err)
	}

	policies, err := loadPolicies()
	if err != nil {
		t.Fatalf("loadPolicies() error: %v", err)
	}
	if len(policies) != 3 {
		t.Fatalf("loadPolicies() returned %d policies, want 3", len(policies))
	}
	byKey := make(map[string]policyInfo, len(policies))
	for _, p := range policies {
		byKey[string(p.Key)] = p
	}

	loginURL, ok := byKey["LoginURL"]
	if !ok {
		t.Fatal("expected LoginURL (pkey.ControlURL) in loaded policies")
	}
	if loginURL.Type != setting.StringValue {
		t.Errorf("LoginURL.Type = %v, want StringValue", loginURL.Type)
	}
	if loginURL.Label == "" || loginURL.Description == "" {
		t.Error("LoginURL has empty Label or Description")
	}
	if loginURL.Category != policydoc.CategoryRuntime {
		t.Errorf("LoginURL.Category = %q, want %q", loginURL.Category, policydoc.CategoryRuntime)
	}

	alwaysOn, ok := byKey["AlwaysOn.Enabled"]
	if !ok {
		t.Fatal("expected AlwaysOn.Enabled in loaded policies")
	}
	if alwaysOn.Type != setting.BooleanValue {
		t.Errorf("AlwaysOn.Enabled.Type = %v, want BooleanValue", alwaysOn.Type)
	}

	dsn, ok := byKey["DeviceSerialNumber"]
	if !ok {
		t.Fatal("expected DeviceSerialNumber in loaded policies")
	}
	if !dsn.Platforms.Has("iOS") {
		t.Errorf("DeviceSerialNumber.Platforms = %v, want to include iOS", dsn.Platforms)
	}
	if dsn.Platforms.Has("windows") {
		t.Errorf("DeviceSerialNumber.Platforms = %v, want NOT to include windows", dsn.Platforms)
	}

	// Results must be sorted by Key.
	for i := 1; i < len(policies); i++ {
		if policies[i-1].Key >= policies[i].Key {
			t.Errorf("policies not sorted: %q >= %q at index %d", policies[i-1].Key, policies[i].Key, i)
		}
	}
}
