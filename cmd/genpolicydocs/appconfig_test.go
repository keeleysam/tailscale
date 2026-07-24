// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/xml"
	"strings"
	"testing"

	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policydoc"
	"tailscale.com/util/syspolicy/setting"
)

func findField(mac managedAppConfiguration, keyName string) *field {
	for _, g := range mac.Presentation.FieldGroups {
		for i, f := range g.Fields {
			if f.KeyName == keyName {
				return &g.Fields[i]
			}
		}
	}
	return nil
}

func findFieldGroup(mac managedAppConfiguration, name string) *fieldGroup {
	for i, g := range mac.Presentation.FieldGroups {
		if g.Name.Language.Text == name {
			return &mac.Presentation.FieldGroups[i]
		}
	}
	return nil
}

func findBooleanKey(mac managedAppConfiguration, keyName string) *booleanKeyElem {
	for i, b := range mac.Dict.Booleans {
		if b.KeyName == keyName {
			return &mac.Dict.Booleans[i]
		}
	}
	return nil
}

func findStringKey(mac managedAppConfiguration, keyName string) *stringKeyElem {
	for i, s := range mac.Dict.Strings {
		if s.KeyName == keyName {
			return &mac.Dict.Strings[i]
		}
	}
	return nil
}

func findStringArrayKey(mac managedAppConfiguration, keyName string) *stringArrayKeyElem {
	for i, s := range mac.Dict.StringArrays {
		if s.KeyName == keyName {
			return &mac.Dict.StringArrays[i]
		}
	}
	return nil
}

func findOption(opts []optionElem, value string) *optionElem {
	for i, o := range opts {
		if o.Value == value {
			return &opts[i]
		}
	}
	return nil
}

// TestRenderAppConfigBooleanDefaultsMatchRuntimeFallback pins renderAppConfig's
// assumption that every BooleanValue key's real unmanaged default is false.
// setting.Definition carries no default-value field to derive this from, so
// renderAppConfig just hardcodes "false" for every BooleanValue key's
// defaultValue. That's correct today (every GetBoolean call site below
// passes false as its own fallback), but nothing else checks it: a future
// BooleanValue key whose real default is true (e.g. pkey.EncryptState is
// true on macOS, see ipn/ipnlocal/local.go's stateEncrypted) would silently
// get an AppConfig defaultValue of "false" if it ever gained iOS/tvOS
// platform support, misrepresenting what leaving it unconfigured does.
// Whoever adds a key here must first verify its real GetBoolean(key, want)
// fallback matches want in every call site.
func TestRenderAppConfigBooleanDefaultsMatchRuntimeFallback(t *testing.T) {
	tests := []struct {
		key  pkey.Key
		want bool // the fallback every GetBoolean(key, ...) call site actually passes
	}{
		{pkey.AllowExitNodeOverride, false},      // ipn/ipnlocal/local.go
		{pkey.AllowTailscaledRestart, false},     // ipn/localapi/localapi.go
		{pkey.AlwaysOn, false},                   // ipn/ipnlocal/local.go, ipn/ipnauth/policy.go, ipn/desktop/extension.go
		{pkey.AlwaysOnOverrideWithReason, false}, // ipn/ipnauth/policy.go
	}
	for _, tt := range tests {
		policies := []policyInfo{
			{Key: tt.key, Type: setting.BooleanValue, Label: "test", Description: "test", Category: policydoc.CategoryRuntime},
		}
		out, err := renderAppConfig(policies, "iOS", "io.tailscale.ipn.ios")
		if err != nil {
			t.Fatalf("renderAppConfig(%q) error: %v", tt.key, err)
		}
		var mac managedAppConfiguration
		if err := xml.Unmarshal(out, &mac); err != nil {
			t.Fatalf("renderAppConfig(%q) output not well-formed: %v", tt.key, err)
		}
		b := findBooleanKey(mac, string(tt.key))
		if b == nil || b.Default == nil {
			t.Fatalf("%q missing boolean key or default", tt.key)
		}
		want := "false"
		if tt.want {
			want = "true"
		}
		if b.Default.Value != want {
			t.Errorf("%q AppConfig defaultValue = %q, want %q (its real GetBoolean fallback)", tt.key, b.Default.Value, want)
		}
	}
}

func TestRenderAppConfig(t *testing.T) {
	policies := []policyInfo{
		{Key: pkey.ControlURL, Type: setting.StringValue, Label: "Coordination server URL", Description: "Require using a specific Tailscale coordination server. See https://tailscale.com/kb/1315/mdm-keys#set-a-custom-control-server-url for details.", Category: policydoc.CategoryRuntime},
		{Key: pkey.AlwaysOn, Type: setting.BooleanValue, Label: "Always On", Description: "Prevent the user from disconnecting.", Category: policydoc.CategoryRuntime},
		{Key: pkey.AllowedSuggestedExitNodes, Type: setting.StringListValue, Label: "Allowed suggested exit nodes", Description: "Restrict which exit nodes may be suggested.", Category: policydoc.CategoryExitNode},
		{Key: pkey.ExitNodeAllowLANAccess, Type: setting.PreferenceOptionValue, Label: "Allow LAN access", Description: "Control LAN access while using an exit node.", Category: policydoc.CategoryExitNode},
		{Key: pkey.ExitNodeMenuVisibility, Type: setting.VisibilityValue, Label: "Show exit node picker", Description: "Show or hide the exit node picker.", Platforms: setting.PlatformList{"macOS", "iOS", "windows", "android", "linux"}, Category: policydoc.CategoryUIVisibility},
		// Not "iOS": explicitly restricted to windows only, must be excluded.
		{Key: pkey.LogSCMInteractions, Type: setting.BooleanValue, Label: "Log SCM interactions", Description: "Windows-only logging.", Platforms: setting.PlatformList{"windows"}, Category: policydoc.CategoryRuntime},
	}

	out, err := renderAppConfig(policies, "iOS", "io.tailscale.ipn.ios")
	if err != nil {
		t.Fatalf("renderAppConfig() error: %v", err)
	}
	if !strings.HasPrefix(string(out), xml.Header) {
		t.Error("output missing XML declaration header")
	}

	var mac managedAppConfiguration
	if err := xml.Unmarshal(out, &mac); err != nil {
		t.Fatalf("output is not well-formed XML: %v\n---\n%s", err, out)
	}

	if mac.BundleID != "io.tailscale.ipn.ios" {
		t.Errorf("BundleID = %q, want io.tailscale.ipn.ios", mac.BundleID)
	}
	if mac.Version != 1 {
		t.Errorf("Version = %d, want 1", mac.Version)
	}
	if findField(mac, "LogSCMInteractions") != nil {
		t.Error("windows-only key LogSCMInteractions should have been filtered out of iOS output")
	}

	loginURL := findField(mac, "LoginURL")
	if loginURL == nil {
		t.Fatal("missing field LoginURL")
	}
	wantDesc := "Require using a specific Tailscale coordination server. See https://tailscale.com/kb/1315/mdm-keys#set-a-custom-control-server-url for details."
	if loginURL.Type != "input" || loginURL.Label == nil || loginURL.Label.Language.Text != "Coordination server URL" || loginURL.Description == nil || loginURL.Description.Language.Text != wantDesc {
		t.Errorf("LoginURL field = %+v, want type=input label=%q description=%q", loginURL, "Coordination server URL", wantDesc)
	}

	alwaysOn := findField(mac, "AlwaysOn.Enabled")
	if alwaysOn == nil || alwaysOn.Description == nil || alwaysOn.Description.Language.Text != "Prevent the user from disconnecting." {
		t.Errorf("AlwaysOn.Enabled field description must be the bare Description with no link appended: %+v", alwaysOn)
	}
	if b := findBooleanKey(mac, "AlwaysOn.Enabled"); b == nil || b.Default == nil || b.Default.Value != "false" {
		t.Errorf("missing boolean key AlwaysOn.Enabled with false default: %+v", b)
	}
	if findStringArrayKey(mac, "AllowedSuggestedExitNodes") == nil {
		t.Error("missing stringArray key AllowedSuggestedExitNodes")
	}

	lanAccess := findField(mac, "ExitNodeAllowLANAccess")
	if lanAccess == nil || lanAccess.Options == nil {
		t.Fatal("missing options for ExitNodeAllowLANAccess (PreferenceOptionValue) field")
	}
	if o := findOption(lanAccess.Options.Option, ""); o == nil || !o.Selected || o.Language.Text != "Not configured" {
		t.Errorf("missing selected 'Not configured' blank option: %+v", o)
	}
	if o := findOption(lanAccess.Options.Option, "always"); o == nil || o.Language.Text != "Always" {
		t.Errorf("missing 'always' option for PreferenceOptionValue field: %+v", o)
	}

	visibility := findField(mac, "ExitNodesPicker")
	if visibility == nil || visibility.Options == nil {
		t.Fatal("missing options for ExitNodesPicker (VisibilityValue) field")
	}
	if o := findOption(visibility.Options.Option, ""); o == nil || !o.Selected || o.Language.Text != "Not configured" {
		t.Errorf("missing selected 'Not configured' blank option: %+v", o)
	}
	if o := findOption(visibility.Options.Option, "show"); o == nil || o.Language.Text != "Show" {
		t.Errorf("missing 'show' option for VisibilityValue field: %+v", o)
	}

	// Fields are grouped into named fieldGroups by Category (matching
	// https://tailscale.com/docs/features/tailscale-system-policies), not
	// dumped into one flat "Tailscale policies (iOS)" group.
	if len(mac.Presentation.FieldGroups) != 3 {
		t.Errorf("got %d fieldGroups, want 3 (%s, %s, %s)", len(mac.Presentation.FieldGroups), policydoc.CategoryRuntime, policydoc.CategoryExitNode, policydoc.CategoryUIVisibility)
	}
	for _, name := range []string{policydoc.CategoryRuntime, policydoc.CategoryExitNode, policydoc.CategoryUIVisibility} {
		g := findFieldGroup(mac, name)
		if g == nil {
			t.Errorf("missing fieldGroup named %q", name)
			continue
		}
		if len(g.Fields) == 0 {
			t.Errorf("fieldGroup %q has no fields", name)
		}
	}
	// LogSCMInteractions is windows-only, so the CategoryRuntime group must
	// still be produced (from LoginURL and AlwaysOn.Enabled) but not
	// duplicated.
	if want, got := 2, len(findFieldGroup(mac, policydoc.CategoryRuntime).Fields); got != want {
		t.Errorf("%q fieldGroup has %d fields, want %d (LoginURL, AlwaysOn.Enabled)", policydoc.CategoryRuntime, got, want)
	}
}

func TestRenderAppConfigUnknownCategory(t *testing.T) {
	policies := []policyInfo{
		{Key: pkey.ControlURL, Type: setting.StringValue, Label: "Coordination server URL", Description: "...", Category: "Some Typo'd Category"},
	}
	if _, err := renderAppConfig(policies, "iOS", "io.tailscale.ipn.ios"); err == nil {
		t.Error("renderAppConfig() with an unrecognized Category succeeded, want an error so the key isn't silently dropped from every fieldGroup")
	}
}

func TestRenderAppConfig_DifferentPlatformsAndBundleID(t *testing.T) {
	policies := []policyInfo{
		// Universal: present for both iOS and tvOS.
		{Key: pkey.ControlURL, Type: setting.StringValue, Label: "Coordination server URL", Description: "Require using a specific Tailscale coordination server.", Category: policydoc.CategoryRuntime},
		// iOS-supported per the visibility platform list, tvOS is not listed: must appear for iOS, not tvOS.
		{Key: pkey.ExitNodeMenuVisibility, Type: setting.VisibilityValue, Label: "Show exit node picker", Description: "Show or hide the exit node picker.", Platforms: setting.PlatformList{"macOS", "iOS", "windows", "android", "linux"}, Category: policydoc.CategoryUIVisibility},
		// tvOS-supported, iOS is not listed: must appear for tvOS, not iOS.
		{Key: pkey.RunExitNodeVisibility, Type: setting.VisibilityValue, Label: "Show run-exit-node option", Description: "Show or hide the run-exit-node menu item.", Platforms: setting.PlatformList{"macOS", "tvOS", "windows", "android", "linux"}, Category: policydoc.CategoryUIVisibility},
	}

	iosOut, err := renderAppConfig(policies, "iOS", "io.tailscale.ipn.ios")
	if err != nil {
		t.Fatalf("renderAppConfig(iOS) error: %v", err)
	}
	tvosOut, err := renderAppConfig(policies, "tvOS", "io.tailscale.ipn.ios")
	if err != nil {
		t.Fatalf("renderAppConfig(tvOS) error: %v", err)
	}

	var iosMAC, tvosMAC managedAppConfiguration
	if err := xml.Unmarshal(iosOut, &iosMAC); err != nil {
		t.Fatalf("iOS output is not well-formed XML: %v", err)
	}
	if err := xml.Unmarshal(tvosOut, &tvosMAC); err != nil {
		t.Fatalf("tvOS output is not well-formed XML: %v", err)
	}

	if findField(iosMAC, "ExitNodesPicker") == nil {
		t.Error("iOS output missing ExitNodesPicker (iOS-supported)")
	}
	if findField(iosMAC, "RunExitNode") != nil {
		t.Error("iOS output should not contain RunExitNode (tvOS-only in this test data)")
	}
	if findField(tvosMAC, "ExitNodesPicker") != nil {
		t.Error("tvOS output should not contain ExitNodesPicker (iOS-only in this test data)")
	}
	if findField(tvosMAC, "RunExitNode") == nil {
		t.Error("tvOS output missing RunExitNode (tvOS-supported)")
	}
	if findField(iosMAC, "LoginURL") == nil || findField(tvosMAC, "LoginURL") == nil {
		t.Error("universal key LoginURL should appear in both iOS and tvOS output")
	}
	if tvosMAC.BundleID != "io.tailscale.ipn.ios" {
		t.Errorf("tvOS BundleID = %q, want io.tailscale.ipn.ios", tvosMAC.BundleID)
	}
}
