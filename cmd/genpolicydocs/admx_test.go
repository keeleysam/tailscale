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

// TestAdmxNameNoCollisions guards against admxName's dot-to-underscore
// collapse mapping two distinct keys to the same identifier (e.g. a future
// "Foo_Bar" key colliding with "Foo.Bar"), which ADMX's schema requires to
// be unique per policy/element name. Runs over every key policydoc knows
// about (policydoc.Entries), not just the well-known-for-test subset used
// elsewhere in this package's tests, since it's exactly the kind of thing
// that should be checked against the full real key set.
func TestAdmxNameNoCollisions(t *testing.T) {
	seen := make(map[string]pkey.Key, len(policydoc.Entries))
	for _, e := range policydoc.Entries {
		name := admxName(string(e.Key))
		if other, ok := seen[name]; ok {
			t.Errorf("admxName collision: %q and %q both normalize to %q", other, e.Key, name)
			continue
		}
		seen[name] = e.Key
	}
}

func findPolicy(defs policyDefinitions, name string) *admxPolicy {
	for i, p := range defs.Policies.Policy {
		if p.Name == name {
			return &defs.Policies.Policy[i]
		}
	}
	return nil
}

func findCategory(defs policyDefinitions, name string) *categoryElem {
	for i, c := range defs.Categories.Category {
		if c.Name == name {
			return &defs.Categories.Category[i]
		}
	}
	return nil
}

func findEnumItem(items []enumItemElem, displayName string) *enumItemElem {
	for i, it := range items {
		if it.DisplayName == displayName {
			return &items[i]
		}
	}
	return nil
}

func TestRenderADMX(t *testing.T) {
	policies := []policyInfo{
		{Key: pkey.ControlURL, Type: setting.StringValue, Scope: setting.DeviceSetting, Label: "Coordination server URL", Description: "Require using a specific Tailscale coordination server.", Category: policydoc.CategoryRuntime},
		{Key: pkey.AllowTailscaledRestart, Type: setting.BooleanValue, Scope: setting.DeviceSetting, Label: "Allow restart", Description: "Allow tailscaled to be restarted.", Category: policydoc.CategoryRuntime},
		{Key: pkey.AllowedSuggestedExitNodes, Type: setting.StringListValue, Scope: setting.DeviceSetting, Label: "Allowed suggested exit nodes", Description: "Restrict which exit nodes may be suggested.", Category: policydoc.CategoryExitNode},
		{Key: pkey.ExitNodeAllowLANAccess, Type: setting.PreferenceOptionValue, Scope: setting.DeviceSetting, Label: "Allow LAN access", Description: "Control LAN access while using an exit node.", Category: policydoc.CategoryExitNode},
		{Key: pkey.EnableDNSRegistration, Type: setting.PreferenceOptionValue, Scope: setting.DeviceSetting, Label: "Register in DNS", Description: "Control DNS registration.", Category: policydoc.CategoryRuntime},
		{Key: pkey.AdminConsoleVisibility, Type: setting.VisibilityValue, Scope: setting.UserSetting, Label: "Show admin console access", Description: "Show or hide the admin console option.", Category: policydoc.CategoryUIVisibility},
		// The AlwaysOn/ExitNodeID/ManagedBy bundles: these six keys should
		// collapse into three hand-composed policies, not six standalone
		// ones.
		{Key: pkey.AlwaysOn, Type: setting.BooleanValue, Scope: setting.DeviceSetting, Label: "Always On", Description: "Prevent the user from disconnecting.", Category: policydoc.CategoryRuntime},
		{Key: pkey.AlwaysOnOverrideWithReason, Type: setting.BooleanValue, Scope: setting.DeviceSetting, Label: "Require reason to override", Description: "Require a reason to override Always On.", Category: policydoc.CategoryRuntime},
		{Key: pkey.ExitNodeID, Type: setting.StringValue, Scope: setting.DeviceSetting, Label: "Forced exit node", Description: "Force the client to always use the given exit node.", Category: policydoc.CategoryExitNode},
		{Key: pkey.AllowExitNodeOverride, Type: setting.BooleanValue, Scope: setting.DeviceSetting, Label: "Allow exit node override", Description: "Allow the user to override the forced exit node.", Category: policydoc.CategoryExitNode},
		{Key: pkey.ManagedByOrganizationName, Type: setting.StringValue, Scope: setting.UserSetting, Label: "Managed-by organization name", Description: "Name of the organization managing this device.", Category: policydoc.CategoryOrganization},
		{Key: pkey.ManagedByCaption, Type: setting.StringValue, Scope: setting.UserSetting, Label: "Managed-by caption", Description: "Support caption text.", Category: policydoc.CategoryOrganization},
		{Key: pkey.ManagedByURL, Type: setting.StringValue, Scope: setting.UserSetting, Label: "Managed-by support URL", Description: "Support URL.", Category: policydoc.CategoryOrganization},
		// Not "windows": must be excluded entirely.
		{Key: pkey.DeviceSerialNumber, Type: setting.StringValue, Scope: setting.DeviceSetting, Label: "Device serial number", Description: "Provide the device serial number.", Platforms: setting.PlatformList{"android", "iOS", "tvOS"}, Category: policydoc.CategoryRuntime},
	}

	out, err := renderADMX(policies)
	if err != nil {
		t.Fatalf("renderADMX() error: %v", err)
	}
	if !strings.HasPrefix(string(out), xml.Header) {
		t.Error("output missing XML declaration header")
	}

	var defs policyDefinitions
	if err := xml.Unmarshal(out, &defs); err != nil {
		t.Fatalf("output is not well-formed XML: %v\n---\n%s", err, out)
	}

	if p := findPolicy(defs, "DeviceSerialNumber"); p != nil {
		t.Error("non-windows-supported key DeviceSerialNumber should have been filtered out")
	}

	// Category tree: one product-root category, five sub-categories nested
	// under it (matching policydoc's taxonomy).
	if root := findCategory(defs, "Top_Category"); root == nil || root.ParentCategory != nil {
		t.Error("missing root Top_Category, or it unexpectedly has its own parent")
	}
	for _, id := range []string{"AutoUpdate_Category", "ExitNode_Category", "Organization_Category", "Runtime_Category", "UIVisibility_Category"} {
		c := findCategory(defs, id)
		if c == nil {
			t.Errorf("missing sub-category %s", id)
			continue
		}
		if c.ParentCategory == nil || c.ParentCategory.Ref != "Top_Category" {
			t.Errorf("sub-category %s must be nested under Top_Category", id)
		}
	}

	loginURL := findPolicy(defs, "LoginURL")
	if loginURL == nil {
		t.Fatal("missing policy LoginURL")
	}
	if loginURL.Class != "Machine" {
		t.Errorf("LoginURL.Class = %q, want Machine (from DeviceSetting scope)", loginURL.Class)
	}
	if loginURL.ParentCategory.Ref != "Runtime_Category" {
		t.Errorf("LoginURL.ParentCategory = %q, want Runtime_Category (its policydoc Category), not the flat root", loginURL.ParentCategory.Ref)
	}
	if loginURL.Elements == nil || len(loginURL.Elements.Text) != 1 || loginURL.Elements.Text[0].ID != "LoginURL" || loginURL.Elements.Text[0].ValueName != "LoginURL" || !loginURL.Elements.Text[0].Required {
		t.Errorf("LoginURL missing required text element with valueName matching the raw key: %+v", loginURL.Elements)
	}

	restart := findPolicy(defs, "AllowTailscaledRestart")
	if restart == nil {
		t.Fatal("missing policy AllowTailscaledRestart")
	}
	if restart.ValueName != "AllowTailscaledRestart" {
		t.Errorf("boolean policy AllowTailscaledRestart.ValueName = %q, want the raw key, or GPO has nothing telling it which registry value to write", restart.ValueName)
	}
	if restart.EnabledValue == nil || restart.EnabledValue.Decimal == nil || restart.EnabledValue.Decimal.Value != "1" {
		t.Error("missing boolean enabledValue=1")
	}
	if restart.DisabledValue == nil || restart.DisabledValue.Decimal == nil || restart.DisabledValue.Decimal.Value != "0" {
		t.Error("missing boolean disabledValue=0")
	}

	suggested := findPolicy(defs, "AllowedSuggestedExitNodes")
	if suggested == nil {
		t.Fatal("missing policy AllowedSuggestedExitNodes")
	}
	if suggested.Key != `Software\Policies\Tailscale\AllowedSuggestedExitNodes` {
		t.Errorf("AllowedSuggestedExitNodes.Key = %q, want its own registry subkey, not the shared one", suggested.Key)
	}
	if suggested.Elements == nil || len(suggested.Elements.List) != 1 || suggested.Elements.List[0].ID != "AllowedSuggestedExitNodes" {
		t.Error("missing list element for AllowedSuggestedExitNodes")
	}

	lanAccess := findPolicy(defs, "ExitNodeAllowLANAccess")
	if lanAccess == nil {
		t.Fatal("missing policy ExitNodeAllowLANAccess")
	}
	if lanAccess.ValueName != "ExitNodeAllowLANAccess" || lanAccess.Elements != nil {
		t.Error("standalone PreferenceOptionValue policy must set valueName directly, not use a nested enum element")
	}
	if lanAccess.EnabledValue == nil || lanAccess.EnabledValue.String == nil || *lanAccess.EnabledValue.String != "always" {
		t.Errorf("ExitNodeAllowLANAccess.EnabledValue = %+v, want string \"always\"", lanAccess.EnabledValue)
	}
	if lanAccess.DisabledValue == nil || lanAccess.DisabledValue.String == nil || *lanAccess.DisabledValue.String != "never" {
		t.Errorf("ExitNodeAllowLANAccess.DisabledValue = %+v, want string \"never\" (its unmanaged default is user-decides, same as every PreferenceOptionValue key except EnableDNSRegistration)", lanAccess.DisabledValue)
	}

	// EnableDNSRegistration is the one PreferenceOptionValue key whose
	// unmanaged default is "never", not "user-decides" (see
	// util/syspolicy/pkey.EnableDNSRegistration's doc comment), so Disabled
	// maps onto "user-decides" here instead of the generic "never", keeping
	// that state reachable as an explicit GPO override.
	dnsReg := findPolicy(defs, "EnableDNSRegistration")
	if dnsReg == nil {
		t.Fatal("missing policy EnableDNSRegistration")
	}
	if dnsReg.EnabledValue == nil || dnsReg.EnabledValue.String == nil || *dnsReg.EnabledValue.String != "always" {
		t.Errorf("EnableDNSRegistration.EnabledValue = %+v, want string \"always\"", dnsReg.EnabledValue)
	}
	if dnsReg.DisabledValue == nil || dnsReg.DisabledValue.String == nil || *dnsReg.DisabledValue.String != "user-decides" {
		t.Errorf("EnableDNSRegistration.DisabledValue = %+v, want string \"user-decides\" (not the generic \"never\", since Not Configured already means \"never\" for this key)", dnsReg.DisabledValue)
	}
	if lanAccess.EnabledValue == nil || lanAccess.EnabledValue.String == nil || *lanAccess.EnabledValue.String != "always" {
		t.Error("standalone PreferenceOptionValue policy must map Enabled to \"always\"")
	}
	if lanAccess.DisabledValue == nil || lanAccess.DisabledValue.String == nil || *lanAccess.DisabledValue.String != "never" {
		t.Error("standalone PreferenceOptionValue policy must map Disabled to \"never\"")
	}

	adminConsole := findPolicy(defs, "AdminConsole")
	if adminConsole == nil {
		t.Fatal("missing AdminConsoleVisibility policy (key \"AdminConsole\")")
	}
	if adminConsole.Class != "Both" {
		t.Errorf("AdminConsole.Class = %q, want Both (from UserSetting scope)", adminConsole.Class)
	}
	if adminConsole.Elements != nil {
		t.Error("standalone VisibilityValue policy must have no elements")
	}
	if adminConsole.EnabledValue == nil || adminConsole.EnabledValue.String == nil || *adminConsole.EnabledValue.String != "show" {
		t.Error("standalone VisibilityValue policy must map Enabled to \"show\"")
	}
	if adminConsole.DisabledValue == nil || adminConsole.DisabledValue.String == nil || *adminConsole.DisabledValue.String != "hide" {
		t.Error("standalone VisibilityValue policy must map Disabled to \"hide\"")
	}

	// AlwaysOn bundle: pkey.AlwaysOn's raw key is "AlwaysOn.Enabled", but the
	// bundle's top-level policy name must stay the bare "AlwaysOn" (matching
	// the hand-written file), not the mechanical admxName derivation
	// ("AlwaysOn_Enabled"): admins already have GPOs configured against that
	// exact name, and renaming it would orphan those settings. Its sibling
	// AlwaysOn.OverrideWithReason must not get a top-level policy of its own.
	if findPolicy(defs, "AlwaysOn_Enabled") != nil {
		t.Error("AlwaysOn bundle must keep the bare policy name \"AlwaysOn\", not the mechanical \"AlwaysOn_Enabled\" derivation, or existing GPO configurations lose their binding")
	}
	if findPolicy(defs, "AlwaysOn_OverrideWithReason") != nil {
		t.Error("AlwaysOn.OverrideWithReason must not get its own top-level policy: it belongs nested inside the AlwaysOn bundle")
	}
	alwaysOn := findPolicy(defs, "AlwaysOn")
	if alwaysOn == nil {
		t.Fatal("missing bundled AlwaysOn policy")
	}
	if alwaysOn.ValueName != "AlwaysOn.Enabled" {
		t.Errorf("AlwaysOn.ValueName = %q, want AlwaysOn.Enabled", alwaysOn.ValueName)
	}
	if alwaysOn.ParentCategory.Ref != "Runtime_Category" {
		t.Errorf("AlwaysOn.ParentCategory = %q, want Runtime_Category (its gate key pkey.AlwaysOn's policydoc Category), not a hardcoded literal", alwaysOn.ParentCategory.Ref)
	}
	if alwaysOn.Elements == nil || len(alwaysOn.Elements.Enum) != 1 || alwaysOn.Elements.Enum[0].ID != "AlwaysOn_OverrideWithReason" || alwaysOn.Elements.Enum[0].ValueName != "AlwaysOn.OverrideWithReason" {
		t.Fatalf("missing nested AlwaysOn.OverrideWithReason enum inside the AlwaysOn bundle: %+v", alwaysOn.Elements)
	}
	if item := findEnumItem(alwaysOn.Elements.Enum[0].Item, "$(string.AllowedWithAudit)"); item == nil || item.Value.Decimal == nil || item.Value.Decimal.Value != "1" {
		t.Error("missing AllowedWithAudit=1 item in the nested AlwaysOn.OverrideWithReason enum")
	}

	// ExitNodeID bundle: one policy with a required text element and a
	// nested enum; ExitNode.AllowOverride must not get its own policy.
	if findPolicy(defs, "ExitNode_AllowOverride") != nil {
		t.Error("ExitNode.AllowOverride must not get its own top-level policy: it belongs nested inside the ExitNodeID bundle")
	}
	exitNodeID := findPolicy(defs, "ExitNodeID")
	if exitNodeID == nil {
		t.Fatal("missing bundled ExitNodeID policy")
	}
	if exitNodeID.Elements == nil || len(exitNodeID.Elements.Text) != 1 || exitNodeID.Elements.Text[0].ID != "ExitNodeID" || !exitNodeID.Elements.Text[0].Required {
		t.Error("missing required ExitNodeID text element inside the ExitNodeID bundle")
	}
	if exitNodeID.ParentCategory.Ref != "ExitNode_Category" {
		t.Errorf("ExitNodeID.ParentCategory = %q, want ExitNode_Category (its gate key pkey.ExitNodeID's policydoc Category), not a hardcoded literal", exitNodeID.ParentCategory.Ref)
	}
	if exitNodeID.Elements == nil || len(exitNodeID.Elements.Enum) != 1 || exitNodeID.Elements.Enum[0].ID != "ExitNode_AllowOverride" || exitNodeID.Elements.Enum[0].ValueName != "ExitNode.AllowOverride" {
		t.Error("missing nested ExitNode.AllowOverride enum inside the ExitNodeID bundle")
	}

	// ManagedBy bundle: one policy grouping three independent text fields,
	// none of which should get its own top-level policy.
	for _, name := range []string{"ManagedByOrganizationName", "ManagedByCaption", "ManagedByURL"} {
		if findPolicy(defs, name) != nil {
			t.Errorf("%s must not get its own top-level policy: it belongs inside the ManagedBy bundle", name)
		}
	}
	managedBy := findPolicy(defs, "ManagedBy")
	if managedBy == nil {
		t.Fatal("missing bundled ManagedBy policy")
	}
	if managedBy.Class != "Both" {
		t.Errorf("ManagedBy.Class = %q, want Both", managedBy.Class)
	}
	if managedBy.ParentCategory.Ref != "Organization_Category" {
		t.Errorf("ManagedBy.ParentCategory = %q, want Organization_Category (its gate key pkey.ManagedByOrganizationName's policydoc Category), not a hardcoded literal", managedBy.ParentCategory.Ref)
	}
	if managedBy.Elements == nil || len(managedBy.Elements.Text) != 3 {
		t.Fatalf("ManagedBy bundle must have exactly 3 text elements, got %+v", managedBy.Elements)
	}
	wantText := []textElem{
		{ID: "ManagedByOrganizationName", ValueName: "ManagedByOrganizationName", Required: true},
		{ID: "ManagedByCaption", ValueName: "ManagedByCaption"},
		{ID: "ManagedByURL", ValueName: "ManagedByURL"},
	}
	for i, want := range wantText {
		if got := managedBy.Elements.Text[i]; got != want {
			t.Errorf("ManagedBy.Elements.Text[%d] = %+v, want %+v", i, got, want)
		}
	}
}

func TestRenderADMXUnknownCategory(t *testing.T) {
	policies := []policyInfo{
		{Key: pkey.ControlURL, Type: setting.StringValue, Scope: setting.DeviceSetting, Label: "Coordination server URL", Description: "...", Category: "Some Typo'd Category"},
	}
	if _, err := renderADMX(policies); err == nil {
		t.Error("renderADMX() with an unrecognized Category succeeded, want an error")
	}
}

func TestRenderADMXUnknownCategoryInBundle(t *testing.T) {
	// pkey.AlwaysOn is the gate key buildAlwaysOnPolicy borrows its category
	// from; it must be validated the same way standalone policies are, not
	// bypassed via a hardcoded category literal.
	policies := []policyInfo{
		{Key: pkey.AlwaysOn, Type: setting.BooleanValue, Scope: setting.DeviceSetting, Label: "Always On", Description: "...", Category: "Some Typo'd Category"},
		{Key: pkey.AlwaysOnOverrideWithReason, Type: setting.BooleanValue, Scope: setting.DeviceSetting, Label: "Require reason to override", Description: "...", Category: "Some Typo'd Category"},
	}
	if _, err := renderADMX(policies); err == nil {
		t.Error("renderADMX() with the AlwaysOn bundle's gate key given an unrecognized Category succeeded, want an error")
	}
}

func TestRenderADMXBundleWindowsInconsistency(t *testing.T) {
	// AlwaysOn itself supports windows, but its nested bundle member
	// AlwaysOnOverrideWithReason doesn't: bundleSupportsWindows would
	// silently drop the whole bundle, including AlwaysOn's own policy,
	// with no signal. renderADMX must error instead.
	policies := []policyInfo{
		{Key: pkey.AlwaysOn, Type: setting.BooleanValue, Scope: setting.DeviceSetting, Label: "Always On", Description: "...", Category: policydoc.CategoryRuntime},
		{Key: pkey.AlwaysOnOverrideWithReason, Type: setting.BooleanValue, Scope: setting.DeviceSetting, Label: "Require reason to override", Description: "...", Category: policydoc.CategoryRuntime, Platforms: setting.PlatformList{"macOS"}},
	}
	if _, err := renderADMX(policies); err == nil {
		t.Error("renderADMX() with a windows-supported gate key and a non-windows bundle member succeeded, want an error rather than silently dropping the gate key's policy")
	}
}

func TestRenderADMXBundleWindowsInconsistencyReverse(t *testing.T) {
	// ManagedBy's three members are co-equal, not gate-and-nested like
	// AlwaysOn/ExitNodeID: there's no single designated key whose Windows
	// support the consistency check can key off. Here it's
	// ManagedByOrganizationName (the key buildManagedByPolicy borrows its
	// Class/Category from) that loses Windows support while its sibling
	// members keep it, the reverse of TestRenderADMXBundleWindowsInconsistency.
	// This must still error, not silently drop ManagedByCaption/ManagedByURL.
	policies := []policyInfo{
		{Key: pkey.ManagedByOrganizationName, Type: setting.StringValue, Scope: setting.UserSetting, Label: "Managed-by organization name", Description: "...", Category: policydoc.CategoryOrganization, Platforms: setting.PlatformList{"macOS"}},
		{Key: pkey.ManagedByCaption, Type: setting.StringValue, Scope: setting.UserSetting, Label: "Managed-by caption", Description: "...", Category: policydoc.CategoryOrganization},
		{Key: pkey.ManagedByURL, Type: setting.StringValue, Scope: setting.UserSetting, Label: "Managed-by support URL", Description: "...", Category: policydoc.CategoryOrganization},
	}
	if _, err := renderADMX(policies); err == nil {
		t.Error("renderADMX() with a non-windows ManagedByOrganizationName and windows-supported sibling members succeeded, want an error rather than silently dropping the bundle")
	}
}
