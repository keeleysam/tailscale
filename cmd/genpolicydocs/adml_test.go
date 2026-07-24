// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/xml"
	"testing"

	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/setting"
)

func findADMLString(res policyDefinitionResources, id string) *admlStringElem {
	for i, s := range res.Resources.StringTable.String {
		if s.ID == id {
			return &res.Resources.StringTable.String[i]
		}
	}
	return nil
}

func findPresentation(res policyDefinitionResources, id string) *presentationEntryElem {
	for i, p := range res.Resources.PresentationTable.Presentation {
		if p.ID == id {
			return &res.Resources.PresentationTable.Presentation[i]
		}
	}
	return nil
}

func TestRenderADML(t *testing.T) {
	policies := []policyInfo{
		{Key: pkey.ControlURL, Type: setting.StringValue, Label: "Coordination server URL", Description: "Require using a specific Tailscale coordination server. See https://tailscale.com/kb/1315/mdm-keys#set-a-custom-control-server-url for details."},
		{Key: pkey.AllowTailscaledRestart, Type: setting.BooleanValue, Label: "Allow restart", Description: "Allow tailscaled to be restarted."},
		{Key: pkey.AllowedSuggestedExitNodes, Type: setting.StringListValue, Label: "Allowed suggested exit nodes", Description: "Restrict which exit nodes may be suggested."},
		{Key: pkey.ExitNodeAllowLANAccess, Type: setting.PreferenceOptionValue, Label: "Allow LAN access", Description: "Control LAN access while using an exit node."},
		{Key: pkey.AdminConsoleVisibility, Type: setting.VisibilityValue, Label: "Show admin console access", Description: "Show or hide the admin console option."},
		// The AlwaysOn/ExitNodeID/ManagedBy bundles: see TestRenderADMX.
		{Key: pkey.AlwaysOn, Type: setting.BooleanValue, Label: "Always On", Description: "Prevent the user from disconnecting."},
		{Key: pkey.AlwaysOnOverrideWithReason, Type: setting.BooleanValue, Label: "Require reason to override", Description: "Require a reason to override Always On."},
		{Key: pkey.ExitNodeID, Type: setting.StringValue, Label: "Forced exit node", Description: "Force the client to always use the given exit node."},
		{Key: pkey.AllowExitNodeOverride, Type: setting.BooleanValue, Label: "Allow exit node override", Description: "Allow the user to override the forced exit node."},
		{Key: pkey.ManagedByOrganizationName, Type: setting.StringValue, Label: "Managed-by organization name", Description: "Name of the organization managing this device."},
		{Key: pkey.ManagedByCaption, Type: setting.StringValue, Label: "Managed-by caption", Description: "Support caption text."},
		{Key: pkey.ManagedByURL, Type: setting.StringValue, Label: "Managed-by support URL", Description: "Support URL."},
		// Not "windows": must be excluded entirely.
		{Key: pkey.DeviceSerialNumber, Type: setting.StringValue, Label: "Device serial number", Description: "Provide the device serial number.", Platforms: setting.PlatformList{"android", "iOS", "tvOS"}},
	}

	out, err := renderADML(policies)
	if err != nil {
		t.Fatalf("renderADML() error: %v", err)
	}
	var res policyDefinitionResources
	if err := xml.Unmarshal(out, &res); err != nil {
		t.Fatalf("output is not well-formed XML: %v\n---\n%s", err, out)
	}

	if findADMLString(res, "DeviceSerialNumber") != nil {
		t.Error("non-windows-supported key DeviceSerialNumber should have been filtered out")
	}
	for id, want := range map[string]string{
		"AutoUpdate_Category":   "Configure the auto-update settings",
		"ExitNode_Category":     "Configure the exit node settings",
		"Organization_Category": "Show contact information for your organization",
		"Runtime_Category":      "Other settings",
		"UIVisibility_Category": "Change the visibility of UI items",
	} {
		if s := findADMLString(res, id); s == nil || s.Value != want {
			t.Errorf("category string %s = %v, want %q", id, s, want)
		}
	}

	if s := findADMLString(res, "LoginURL"); s == nil || s.Value != "Coordination server URL" {
		t.Errorf("LoginURL display-name string = %v, want %q", s, "Coordination server URL")
	}
	wantHelp := "Require using a specific Tailscale coordination server. See https://tailscale.com/kb/1315/mdm-keys#set-a-custom-control-server-url for details."
	if s := findADMLString(res, "LoginURL_Help"); s == nil || s.Value != wantHelp {
		t.Errorf("LoginURL_Help = %v, want the Description verbatim (KB link included): %q", s, wantHelp)
	}
	if s := findADMLString(res, "AllowTailscaledRestart_Help"); s == nil || s.Value != "Allow tailscaled to be restarted." {
		t.Errorf("AllowTailscaledRestart_Help = %v, want the bare Description (no link appended when it has none)", s)
	}
	if findPresentation(res, "LoginURL") == nil {
		t.Error("missing textBox presentation for LoginURL")
	}
	// Boolean, PreferenceOptionValue, and VisibilityValue keys all render
	// as a checkbox or Enabled/Disabled radio with no elements, so none of
	// them get a presentation entry.
	for _, id := range []string{"AllowTailscaledRestart", "ExitNodeAllowLANAccess", "AdminConsole"} {
		if findPresentation(res, id) != nil {
			t.Errorf("%s has no elements and should not have a presentation entry", id)
		}
	}
	if s := findADMLString(res, "AllowTailscaledRestart"); s == nil || s.Value != "Allow restart" {
		t.Errorf("AllowTailscaledRestart display-name string = %v, want %q", s, "Allow restart")
	}
	if s := findADMLString(res, "ExitNodeAllowLANAccess"); s == nil || s.Value != "Allow LAN access" {
		t.Errorf("ExitNodeAllowLANAccess display-name string = %v, want %q", s, "Allow LAN access")
	}
	if s := findADMLString(res, "AdminConsole"); s == nil || s.Value != "Show admin console access" {
		t.Errorf("AdminConsole (AdminConsoleVisibility) display-name string = %v, want %q", s, "Show admin console access")
	}
	if p := findPresentation(res, "AllowedSuggestedExitNodes"); p == nil || p.ListBox == nil || p.ListBox.RefID != "AllowedSuggestedExitNodes" {
		t.Error("missing listBox presentation for AllowedSuggestedExitNodes")
	}

	// AlwaysOn bundle: one combined presentation, no entry for its nested
	// sibling, and the shared override-choice strings.
	if findADMLString(res, "AlwaysOn_OverrideWithReason") != nil {
		t.Error("AlwaysOn.OverrideWithReason must not have its own string-table entry: its label is inline in the AlwaysOn presentation")
	}
	if p := findPresentation(res, "AlwaysOn"); p == nil ||
		p.IntroText != "The options below allow configuring exceptions where disconnecting Tailscale is permitted." ||
		p.DropdownList == nil || p.DropdownList.RefID != "AlwaysOn_OverrideWithReason" || p.DropdownList.Text != "Disconnects with reason:" {
		t.Errorf("missing combined AlwaysOn presentation (intro text + override dropdown): %+v", p)
	}
	if s := findADMLString(res, "AllowedWithAudit"); s == nil || s.Value != "Allowed (with audit)" {
		t.Errorf("shared AllowedWithAudit string = %v, want %q", s, "Allowed (with audit)")
	}

	// ExitNodeID bundle: one combined presentation with a textBox and a
	// dropdown, no entry for its nested sibling.
	if findADMLString(res, "ExitNode_AllowOverride") != nil {
		t.Error("ExitNode.AllowOverride must not have its own string-table entry: its label is inline in the ExitNodeID presentation")
	}
	if p := findPresentation(res, "ExitNodeID"); p == nil ||
		len(p.TextBox) != 1 || p.TextBox[0].RefID != "ExitNodeID" || p.TextBox[0].Label != "Exit Node:" ||
		p.DropdownList == nil || p.DropdownList.RefID != "ExitNode_AllowOverride" || p.DropdownList.Text != "User override:" {
		t.Errorf("missing combined ExitNodeID presentation (textBox + override dropdown): %+v", p)
	}

	// ManagedBy bundle: one combined presentation with three textBoxes; its
	// three keys have no string-table or presentation entries of their own.
	for _, id := range []string{"ManagedByOrganizationName", "ManagedByCaption", "ManagedByURL"} {
		if findADMLString(res, id) != nil {
			t.Errorf("%s must not have its own string-table entry: it's folded into the ManagedBy bundle", id)
		}
	}
	if s := findADMLString(res, "ManagedBy"); s == nil || s.Value != `Show the "Managed By {Organization}" menu item` {
		t.Errorf("ManagedBy bundle display-name string = %v", s)
	}
	managedBy := findPresentation(res, "ManagedBy")
	if managedBy == nil || len(managedBy.TextBox) != 3 {
		t.Fatalf("missing combined ManagedBy presentation (three textBoxes): %+v", managedBy)
	}
	wantTextBoxes := []textBoxElem{
		{RefID: "ManagedByOrganizationName", Label: "Organization Name:"},
		{RefID: "ManagedByCaption", Label: "Custom Message:"},
		{RefID: "ManagedByURL", Label: "Support URL:"},
	}
	for i, want := range wantTextBoxes {
		if got := managedBy.TextBox[i]; got != want {
			t.Errorf("ManagedBy.TextBox[%d] = %+v, want %+v", i, got, want)
		}
	}
}
