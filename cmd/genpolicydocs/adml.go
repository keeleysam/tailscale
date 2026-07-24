// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/xml"
	"fmt"

	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/setting"
)

type policyDefinitionResources struct {
	XMLName       xml.Name          `xml:"policyDefinitionResources"`
	Revision      string            `xml:"revision,attr"`
	SchemaVersion string            `xml:"schemaVersion,attr"`
	Xmlns         string            `xml:"xmlns,attr"`
	DisplayName   string            `xml:"displayName"`
	Description   string            `xml:"description"`
	Resources     admlResourcesElem `xml:"resources"`
}

type admlResourcesElem struct {
	StringTable       stringTableElem       `xml:"stringTable"`
	PresentationTable presentationTableElem `xml:"presentationTable"`
}

type stringTableElem struct {
	String []admlStringElem `xml:"string"`
}

type admlStringElem struct {
	ID    string `xml:"id,attr"`
	Value string `xml:",chardata"`
}

type presentationTableElem struct {
	Presentation []presentationEntryElem `xml:"presentation"`
}

// presentationEntryElem's fields are declared in the order they must
// render in: a bundle's intro text (if any) before its text boxes, before
// its dropdown. Every bundle below happens to want that same order, so one
// fixed field order covers all of them.
type presentationEntryElem struct {
	ID           string            `xml:"id,attr"`
	IntroText    string            `xml:"text,omitempty"`
	TextBox      []textBoxElem     `xml:"textBox,omitempty"`
	ListBox      *listBoxElem      `xml:"listBox,omitempty"`
	DropdownList *dropdownListElem `xml:"dropdownList,omitempty"`
}

type textBoxElem struct {
	RefID string `xml:"refId,attr"`
	Label string `xml:"label"`
}

type listBoxElem struct {
	RefID string `xml:"refId,attr"`
	Text  string `xml:",chardata"`
}

type dropdownListElem struct {
	RefID       string `xml:"refId,attr"`
	NoSort      bool   `xml:"noSort,attr,omitempty"`
	DefaultItem string `xml:"defaultItem,attr,omitempty"`
	Text        string `xml:",chardata"`
}

const admlKBURL = "https://tailscale.com/kb/1315/mdm-keys"

// renderADML builds the Windows ADML localized-resources document matching
// the ADMX document renderADMX produces for the same policies slice: one
// string-table entry pair (display name + help text) and one presentation
// entry per Windows-supported policy.
func renderADML(policies []policyInfo) ([]byte, error) {
	res := policyDefinitionResources{
		Revision:      "1.0",
		SchemaVersion: "1.0",
		Xmlns:         "http://www.microsoft.com/GroupPolicy/PolicyDefinitions",
		DisplayName:   "Tailscale",
		Description:   "A set of policies that enforces particular settings in the Tailscale Windows client.",
	}
	res.Resources.StringTable.String = []admlStringElem{
		{ID: "TAILSCALE_PRODUCT", Value: "Tailscale"},
		{ID: "SUPPORTED_ALL", Value: "Tailscale (see tailscale.com/kb/1315/mdm-keys for version requirements)"},
		{ID: "Tailscale_Category", Value: "Tailscale"},
	}
	for _, cat := range categoryOrder {
		res.Resources.StringTable.String = append(res.Resources.StringTable.String, admlStringElem{ID: admxCategoryIDs[cat], Value: cat})
	}
	res.Resources.StringTable.String = append(res.Resources.StringTable.String,
		// Shared item labels for the nested override choices bundled into
		// buildAlwaysOnPolicy and buildExitNodeIDPolicy in admx.go.
		admlStringElem{ID: "NotAllowed", Value: "Not Allowed"},
		admlStringElem{ID: "Allowed", Value: "Allowed"},
		admlStringElem{ID: "AllowedWithAudit", Value: "Allowed (with audit)"},
		// ManagedBy has no single policyInfo entry to borrow a display
		// name/help text from: see buildManagedByPolicy in admx.go.
		admlStringElem{ID: "ManagedBy", Value: `Show the "Managed By {Organization}" menu item`},
		admlStringElem{ID: "ManagedBy_Help", Value: `Configure the "Managed By {Organization}" item shown in the Tailscale client, e.g. "Managed By Example Corp". Optionally provide a custom message shown when a user clicks the item, and a URL to a help desk or other support resource for users in the organization. Leave the organization name unset to hide the item entirely. See ` + admlKBURL + " for details."},
	)

	byKey := make(map[pkey.Key]policyInfo, len(policies))
	for _, p := range policies {
		byKey[p.Key] = p
	}

	for _, p := range policies {
		if !p.Platforms.Has("windows") {
			continue
		}
		if admxBundleNestedKeys[p.Key] {
			// No string-table or presentation entry of its own: it's
			// folded into a bundle above whose labels are inline literals.
			continue
		}
		name := bundleName(p.Key)
		res.Resources.StringTable.String = append(res.Resources.StringTable.String,
			admlStringElem{ID: name, Value: p.Label},
			admlStringElem{ID: name + "_Help", Value: p.Description},
		)
		if admxBundleGateKeys[p.Key] {
			// Its presentation is hand-built below alongside its bundle.
			continue
		}
		switch p.Type {
		case setting.BooleanValue, setting.PreferenceOptionValue, setting.VisibilityValue:
			// No elements, so no presentation entry: a checkbox is
			// self-explanatory from the policy's display name and help
			// text alone.
		case setting.StringValue, setting.DurationValue:
			res.Resources.PresentationTable.Presentation = append(res.Resources.PresentationTable.Presentation, presentationEntryElem{
				ID:      name,
				TextBox: []textBoxElem{{RefID: name, Label: p.Label + ":"}},
			})
		case setting.StringListValue:
			res.Resources.PresentationTable.Presentation = append(res.Resources.PresentationTable.Presentation, presentationEntryElem{
				ID:      name,
				ListBox: &listBoxElem{RefID: name, Text: p.Label + ":"},
			})
		default:
			return nil, fmt.Errorf("policy %q has unsupported type %v for ADML generation", p.Key, p.Type)
		}
	}
	if bundleSupportsWindows(byKey, pkey.AlwaysOn, pkey.AlwaysOnOverrideWithReason) {
		res.Resources.PresentationTable.Presentation = append(res.Resources.PresentationTable.Presentation, presentationEntryElem{
			ID:           bundleName(pkey.AlwaysOn),
			IntroText:    "The options below allow configuring exceptions where disconnecting Tailscale is permitted.",
			DropdownList: &dropdownListElem{RefID: admxName(string(pkey.AlwaysOnOverrideWithReason)), NoSort: true, DefaultItem: "0", Text: "Disconnects with reason:"},
		})
	}
	if bundleSupportsWindows(byKey, pkey.ExitNodeID, pkey.AllowExitNodeOverride) {
		res.Resources.PresentationTable.Presentation = append(res.Resources.PresentationTable.Presentation, presentationEntryElem{
			ID:           admxName(string(pkey.ExitNodeID)),
			TextBox:      []textBoxElem{{RefID: admxName(string(pkey.ExitNodeID)), Label: "Exit Node:"}},
			DropdownList: &dropdownListElem{RefID: admxName(string(pkey.AllowExitNodeOverride)), NoSort: true, DefaultItem: "0", Text: "User override:"},
		})
	}
	if bundleSupportsWindows(byKey, pkey.ManagedByOrganizationName, pkey.ManagedByCaption, pkey.ManagedByURL) {
		res.Resources.PresentationTable.Presentation = append(res.Resources.PresentationTable.Presentation, presentationEntryElem{
			ID: "ManagedBy",
			TextBox: []textBoxElem{
				{RefID: admxName(string(pkey.ManagedByOrganizationName)), Label: "Organization Name:"},
				{RefID: admxName(string(pkey.ManagedByCaption)), Label: "Custom Message:"},
				{RefID: admxName(string(pkey.ManagedByURL)), Label: "Support URL:"},
			},
		})
	}

	body, err := xml.MarshalIndent(res, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling ADML XML: %w", err)
	}
	out := make([]byte, 0, len(xml.Header)+len(body)+1)
	out = append(out, []byte(xml.Header)...)
	out = append(out, body...)
	out = append(out, '\n')
	return out, nil
}
