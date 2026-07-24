// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/xml"
	"fmt"
	"strings"

	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policydoc"
	"tailscale.com/util/syspolicy/ptype"
	"tailscale.com/util/syspolicy/setting"
)

// registryKeyPath is the shared registry key under which most policies are
// stored. StringListValue policies get their own subkey instead, since a
// GPO <list> element's numbered values would otherwise collide with other
// policies' plain values under the same key.
const registryKeyPath = `Software\Policies\Tailscale`

// admxName returns a safe, dot-free ADMX policy/element identifier for a
// policy key. The actual dotted key string (e.g. "AlwaysOn.Enabled") is
// preserved wherever it matters for runtime behavior: the valueName and key
// attributes.
func admxName(key string) string {
	return strings.ReplaceAll(key, ".", "_")
}

type policyDefinitions struct {
	XMLName          xml.Name         `xml:"policyDefinitions"`
	Revision         string           `xml:"revision,attr"`
	SchemaVersion    string           `xml:"schemaVersion,attr"`
	Xmlns            string           `xml:"xmlns,attr"`
	PolicyNamespaces policyNamespaces `xml:"policyNamespaces"`
	Resources        resourcesElem    `xml:"resources"`
	SupportedOn      supportedOnDefs  `xml:"supportedOn"`
	Categories       categoriesElem   `xml:"categories"`
	Policies         policiesElem     `xml:"policies"`
}

type policyNamespaces struct {
	Target targetElem `xml:"target"`
}

type targetElem struct {
	Prefix    string `xml:"prefix,attr"`
	Namespace string `xml:"namespace,attr"`
}

type resourcesElem struct {
	MinRequiredRevision string `xml:"minRequiredRevision,attr"`
}

type supportedOnDefs struct {
	Products    productsElem    `xml:"products"`
	Definitions definitionsElem `xml:"definitions"`
}

type productsElem struct {
	Product productElem `xml:"product"`
}

type productElem struct {
	Name         string           `xml:"name,attr"`
	DisplayName  string           `xml:"displayName,attr"`
	MajorVersion majorVersionElem `xml:"majorVersion"`
}

type majorVersionElem struct {
	Name         string `xml:"name,attr"`
	DisplayName  string `xml:"displayName,attr"`
	VersionIndex string `xml:"versionIndex,attr"`
}

type definitionsElem struct {
	Definition []definitionElem `xml:"definition"`
}

type definitionElem struct {
	Name        string  `xml:"name,attr"`
	DisplayName string  `xml:"displayName,attr"`
	And         andElem `xml:"and"`
}

type andElem struct {
	Reference referenceElem `xml:"reference"`
}

type referenceElem struct {
	Ref string `xml:"ref,attr"`
}

type categoriesElem struct {
	Category []categoryElem `xml:"category"`
}

type categoryElem struct {
	Name           string              `xml:"name,attr"`
	DisplayName    string              `xml:"displayName,attr"`
	ParentCategory *parentCategoryElem `xml:"parentCategory,omitempty"`
}

type policiesElem struct {
	Policy []admxPolicy `xml:"policy"`
}

type admxPolicy struct {
	Name           string             `xml:"name,attr"`
	Class          string             `xml:"class,attr"`
	DisplayName    string             `xml:"displayName,attr"`
	ExplainText    string             `xml:"explainText,attr"`
	Presentation   string             `xml:"presentation,attr,omitempty"`
	Key            string             `xml:"key,attr"`
	ValueName      string             `xml:"valueName,attr,omitempty"`
	ParentCategory parentCategoryElem `xml:"parentCategory"`
	SupportedOnRef supportedOnRefElem `xml:"supportedOn"`
	EnabledValue   *valueElem         `xml:"enabledValue,omitempty"`
	DisabledValue  *valueElem         `xml:"disabledValue,omitempty"`
	Elements       *elementsElem      `xml:"elements,omitempty"`
}

type parentCategoryElem struct {
	Ref string `xml:"ref,attr"`
}

type supportedOnRefElem struct {
	Ref string `xml:"ref,attr"`
}

type valueElem struct {
	Decimal *decimalElem `xml:"decimal,omitempty"`
	String  *string      `xml:"string,omitempty"`
}

type decimalElem struct {
	Value string `xml:"value,attr"`
}

type elementsElem struct {
	Text []textElem `xml:"text,omitempty"`
	List []listElem `xml:"list,omitempty"`
	Enum []enumElem `xml:"enum,omitempty"`
}

type textElem struct {
	ID        string `xml:"id,attr"`
	ValueName string `xml:"valueName,attr"`
	Required  bool   `xml:"required,attr,omitempty"`
}

type listElem struct {
	ID string `xml:"id,attr"`
}

type enumElem struct {
	ID        string         `xml:"id,attr"`
	ValueName string         `xml:"valueName,attr"`
	Item      []enumItemElem `xml:"item"`
}

type enumItemElem struct {
	DisplayName string            `xml:"displayName,attr"`
	Value       enumItemValueElem `xml:"value"`
}

// enumItemValueElem holds either a string or a decimal enum item value:
// string for policies whose registry value is one of Tailscale's own
// string constants (e.g. "always"/"never"), decimal for the handful of
// nested boolean-shaped choices bundled into a parent policy below (see
// buildAlwaysOnPolicy, buildExitNodeIDPolicy) that need custom item labels
// a plain <boolean> element can't provide.
type enumItemValueElem struct {
	String  *string      `xml:"string,omitempty"`
	Decimal *decimalElem `xml:"decimal,omitempty"`
}

// admxBundleGateKeys are folded into a hand-composed multi-element policy
// (see buildAlwaysOnPolicy, buildExitNodeIDPolicy) instead of getting their
// own top-level policy from the generic per-key loop below, but still
// contribute their usual ADML display-name/help-text strings since the
// bundle reuses them. This bundling isn't derivable from the flat
// util/syspolicy registry: it mirrors how the hand-written tailscale.admx
// grouped a setting with a related one that only makes sense once the
// first is configured (e.g. overriding Always On with a reason requires
// Always On to be enabled at all).
var admxBundleGateKeys = map[pkey.Key]bool{
	pkey.AlwaysOn:   true,
	pkey.ExitNodeID: true,
}

// admxBundleNestedKeys are folded into a hand-composed multi-element policy
// below and have no ADML presence of their own: their labels are literals
// inline in the bundle's combined presentation, matching the hand-written
// file's original nested-element labels.
var admxBundleNestedKeys = map[pkey.Key]bool{
	pkey.AlwaysOnOverrideWithReason: true,
	pkey.AllowExitNodeOverride:      true,
	pkey.ManagedByOrganizationName:  true,
	pkey.ManagedByCaption:           true,
	pkey.ManagedByURL:               true,
}

// bundleSupportsWindows reports whether every one of keys supports Windows.
// A bundled policy is presented as one unit, so it must not be emitted (by
// either renderADMX or renderADML) unless all of its member keys, gate and
// nested alike, actually apply on Windows: restricting just one nested key
// to a non-Windows platform later must not silently keep showing it via an
// otherwise-Windows-supported bundle.
func bundleSupportsWindows(byKey map[pkey.Key]policyInfo, keys ...pkey.Key) bool {
	for _, k := range keys {
		if !byKey[k].Platforms.Has("windows") {
			return false
		}
	}
	return true
}

// buildBundleIfWindowsSupported builds a bundled policy via build if every
// key in members supports Windows, and returns it for the caller to append.
// If no member supports Windows, the bundle legitimately doesn't apply and
// this returns (nil, nil). If members disagree (at least one supports
// Windows, at least one doesn't), silently skipping (as bundleSupportsWindows
// alone would) would drop every member's contribution to the bundle from the
// output with no signal, so this errors instead. There's no single "gate"
// key to check here: for bundles like ManagedBy, whose members are co-equal
// rather than one gating the others, any member could be the one that keeps
// Windows support while the bundle as a whole loses it.
func buildBundleIfWindowsSupported(byKey map[pkey.Key]policyInfo, members []pkey.Key, build func(map[pkey.Key]policyInfo) (admxPolicy, error)) (*admxPolicy, error) {
	if bundleSupportsWindows(byKey, members...) {
		p, err := build(byKey)
		if err != nil {
			return nil, err
		}
		return &p, nil
	}
	for _, k := range members {
		if byKey[k].Platforms.Has("windows") {
			return nil, fmt.Errorf("bundle member %q supports windows but at least one other member of %v does not; refusing to silently drop the bundle from the ADMX output", k, members)
		}
	}
	return nil, nil
}

func strPtr(s string) *string { return &s }

// admxBundleNames overrides the mechanical admxName derivation for bundles
// whose gate key's raw string contains a "." that would otherwise produce
// a different top-level identifier than the bundle's own name. pkey.AlwaysOn
// is "AlwaysOn.Enabled", but the ADMX policy this bundle produces is named
// "AlwaysOn" (matching the hand-written file, and matching the fact that
// admins already have GPOs configured against that exact name). Keys not
// listed here use admxName's normal per-key derivation.
var admxBundleNames = map[pkey.Key]string{
	pkey.AlwaysOn: "AlwaysOn",
}

// bundleName returns the ADMX/ADML identifier for key, honoring
// admxBundleNames overrides where present.
func bundleName(key pkey.Key) string {
	if name, ok := admxBundleNames[key]; ok {
		return name
	}
	return admxName(string(key))
}

// admxCategoryIDs maps each policydoc.Category* constant to the ADMX
// category element's internal name attribute (an identifier, never shown to
// admins; the category's displayName attribute, resolved via ADML, is what
// they actually see). All five sit under "Top_Category" (the Tailscale
// product root), the same two-level shape the hand-written file used for
// its own Top/UI/Settings split, just with policydoc's five categories
// (shared with appconfig.go's field groups) instead of that file's own
// three.
var admxCategoryIDs = map[string]string{
	policydoc.CategoryAutoUpdate:   "AutoUpdate_Category",
	policydoc.CategoryExitNode:     "ExitNode_Category",
	policydoc.CategoryOrganization: "Organization_Category",
	policydoc.CategoryRuntime:      "Runtime_Category",
	policydoc.CategoryUIVisibility: "UIVisibility_Category",
}

func classForScope(scope setting.Scope) string {
	if scope == setting.UserSetting {
		return "Both"
	}
	return "Machine"
}

// buildAlwaysOnPolicy reconstructs the hand-written file's bundled AlwaysOn
// policy: a checkbox for pkey.AlwaysOn plus a nested override-reason choice
// for pkey.AlwaysOnOverrideWithReason, which is only meaningful once
// AlwaysOn itself is enabled.
func buildAlwaysOnPolicy(byKey map[pkey.Key]policyInfo) (admxPolicy, error) {
	name := bundleName(pkey.AlwaysOn)
	overrideName := admxName(string(pkey.AlwaysOnOverrideWithReason))
	categoryID, ok := admxCategoryIDs[byKey[pkey.AlwaysOn].Category]
	if !ok {
		return admxPolicy{}, fmt.Errorf("policy %q has unknown category %q", pkey.AlwaysOn, byKey[pkey.AlwaysOn].Category)
	}
	return admxPolicy{
		Name:           name,
		Class:          classForScope(byKey[pkey.AlwaysOn].Scope),
		DisplayName:    "$(string." + name + ")",
		ExplainText:    "$(string." + name + "_Help)",
		Presentation:   "$(presentation." + name + ")",
		Key:            registryKeyPath,
		ValueName:      string(pkey.AlwaysOn),
		ParentCategory: parentCategoryElem{Ref: categoryID},
		SupportedOnRef: supportedOnRefElem{Ref: "SUPPORTED_ALL"},
		EnabledValue:   &valueElem{Decimal: &decimalElem{Value: "1"}},
		DisabledValue:  &valueElem{Decimal: &decimalElem{Value: "0"}},
		Elements: &elementsElem{Enum: []enumElem{{
			ID:        overrideName,
			ValueName: string(pkey.AlwaysOnOverrideWithReason),
			Item: []enumItemElem{
				{DisplayName: "$(string.NotAllowed)", Value: enumItemValueElem{Decimal: &decimalElem{Value: "0"}}},
				{DisplayName: "$(string.AllowedWithAudit)", Value: enumItemValueElem{Decimal: &decimalElem{Value: "1"}}},
			},
		}}},
	}, nil
}

// buildExitNodeIDPolicy reconstructs the hand-written file's bundled
// ExitNodeID policy: a required text field for pkey.ExitNodeID plus a
// nested override choice for pkey.AllowExitNodeOverride, which is only
// meaningful once a forced exit node is actually set.
func buildExitNodeIDPolicy(byKey map[pkey.Key]policyInfo) (admxPolicy, error) {
	name := admxName(string(pkey.ExitNodeID))
	overrideName := admxName(string(pkey.AllowExitNodeOverride))
	categoryID, ok := admxCategoryIDs[byKey[pkey.ExitNodeID].Category]
	if !ok {
		return admxPolicy{}, fmt.Errorf("policy %q has unknown category %q", pkey.ExitNodeID, byKey[pkey.ExitNodeID].Category)
	}
	return admxPolicy{
		Name:           name,
		Class:          classForScope(byKey[pkey.ExitNodeID].Scope),
		DisplayName:    "$(string." + name + ")",
		ExplainText:    "$(string." + name + "_Help)",
		Presentation:   "$(presentation." + name + ")",
		Key:            registryKeyPath,
		ParentCategory: parentCategoryElem{Ref: categoryID},
		SupportedOnRef: supportedOnRefElem{Ref: "SUPPORTED_ALL"},
		Elements: &elementsElem{
			Text: []textElem{{ID: name, ValueName: string(pkey.ExitNodeID), Required: true}},
			Enum: []enumElem{{
				ID:        overrideName,
				ValueName: string(pkey.AllowExitNodeOverride),
				Item: []enumItemElem{
					{DisplayName: "$(string.NotAllowed)", Value: enumItemValueElem{Decimal: &decimalElem{Value: "0"}}},
					{DisplayName: "$(string.Allowed)", Value: enumItemValueElem{Decimal: &decimalElem{Value: "1"}}},
				},
			}},
		},
	}, nil
}

// buildManagedByPolicy reconstructs the hand-written file's bundled
// ManagedBy policy: three independent text fields (org name, caption,
// support URL) that describe the same "Managed by" client UI message and
// are naturally edited together. Unlike AlwaysOn and ExitNodeID, none of
// its three keys is a natural stand-in for the whole group, so its display
// name and help text are their own literal strings rather than borrowed
// from a single policyInfo entry.
func buildManagedByPolicy(byKey map[pkey.Key]policyInfo) (admxPolicy, error) {
	orgName := admxName(string(pkey.ManagedByOrganizationName))
	captionName := admxName(string(pkey.ManagedByCaption))
	urlName := admxName(string(pkey.ManagedByURL))
	categoryID, ok := admxCategoryIDs[byKey[pkey.ManagedByOrganizationName].Category]
	if !ok {
		return admxPolicy{}, fmt.Errorf("policy %q has unknown category %q", pkey.ManagedByOrganizationName, byKey[pkey.ManagedByOrganizationName].Category)
	}
	return admxPolicy{
		Name:           "ManagedBy",
		Class:          classForScope(byKey[pkey.ManagedByOrganizationName].Scope),
		DisplayName:    "$(string.ManagedBy)",
		ExplainText:    "$(string.ManagedBy_Help)",
		Presentation:   "$(presentation.ManagedBy)",
		Key:            registryKeyPath,
		ParentCategory: parentCategoryElem{Ref: categoryID},
		SupportedOnRef: supportedOnRefElem{Ref: "SUPPORTED_ALL"},
		Elements: &elementsElem{Text: []textElem{
			{ID: orgName, ValueName: string(pkey.ManagedByOrganizationName), Required: true},
			{ID: captionName, ValueName: string(pkey.ManagedByCaption)},
			{ID: urlName, ValueName: string(pkey.ManagedByURL)},
		}},
	}, nil
}

// renderADMX builds the Windows ADMX policy-definitions document for every
// policy in policies that supports Windows, per [setting.PlatformList.Has].
func renderADMX(policies []policyInfo) ([]byte, error) {
	defs := policyDefinitions{
		Revision:      "1.0",
		SchemaVersion: "1.0",
		Xmlns:         "http://www.microsoft.com/GroupPolicy/PolicyDefinitions",
		PolicyNamespaces: policyNamespaces{
			Target: targetElem{Prefix: "tailscale", Namespace: "Tailscale.Policies"},
		},
		Resources: resourcesElem{MinRequiredRevision: "1.0"},
		SupportedOn: supportedOnDefs{
			Products: productsElem{
				Product: productElem{
					Name:        "TAILSCALE_PRODUCT",
					DisplayName: "$(string.TAILSCALE_PRODUCT)",
					MajorVersion: majorVersionElem{
						Name:         "TAILSCALE_V1",
						DisplayName:  "$(string.TAILSCALE_PRODUCT)",
						VersionIndex: "1",
					},
				},
			},
			Definitions: definitionsElem{
				Definition: []definitionElem{{
					Name:        "SUPPORTED_ALL",
					DisplayName: "$(string.SUPPORTED_ALL)",
					And:         andElem{Reference: referenceElem{Ref: "TAILSCALE_PRODUCT"}},
				}},
			},
		},
		Categories: categoriesElem{
			Category: []categoryElem{{Name: "Top_Category", DisplayName: "$(string.Tailscale_Category)"}},
		},
	}
	for _, cat := range categoryOrder {
		id := admxCategoryIDs[cat]
		defs.Categories.Category = append(defs.Categories.Category, categoryElem{
			Name:           id,
			DisplayName:    "$(string." + id + ")",
			ParentCategory: &parentCategoryElem{Ref: "Top_Category"},
		})
	}

	byKey := make(map[pkey.Key]policyInfo, len(policies))
	for _, p := range policies {
		byKey[p.Key] = p
	}

	for _, p := range policies {
		if !p.Platforms.Has("windows") {
			continue
		}
		if admxBundleGateKeys[p.Key] || admxBundleNestedKeys[p.Key] {
			continue
		}
		categoryID, ok := admxCategoryIDs[p.Category]
		if !ok {
			return nil, fmt.Errorf("policy %q has unknown category %q", p.Key, p.Category)
		}
		name := admxName(string(p.Key))
		policy := admxPolicy{
			Name:           name,
			Class:          classForScope(p.Scope),
			DisplayName:    "$(string." + name + ")",
			ExplainText:    "$(string." + name + "_Help)",
			Key:            registryKeyPath,
			ParentCategory: parentCategoryElem{Ref: categoryID},
			SupportedOnRef: supportedOnRefElem{Ref: "SUPPORTED_ALL"},
		}
		switch p.Type {
		case setting.BooleanValue:
			policy.ValueName = string(p.Key)
			policy.EnabledValue = &valueElem{Decimal: &decimalElem{Value: "1"}}
			policy.DisabledValue = &valueElem{Decimal: &decimalElem{Value: "0"}}
		case setting.StringValue, setting.DurationValue:
			policy.Presentation = "$(presentation." + name + ")"
			policy.Elements = &elementsElem{Text: []textElem{{ID: name, ValueName: string(p.Key), Required: true}}}
		case setting.StringListValue:
			policy.Key = registryKeyPath + `\` + string(p.Key)
			policy.Presentation = "$(presentation." + name + ")"
			policy.Elements = &elementsElem{List: []listElem{{ID: name}}}
		case setting.PreferenceOptionValue:
			// Enabled/Disabled map onto Tailscale's own "always"/"never"
			// values; leaving the policy Not Configured is what maps onto
			// the third real value, "user-decides", for every key except
			// pkey.EnableDNSRegistration, whose unmanaged default is
			// "never" instead (see its doc comment in
			// util/syspolicy/pkey/pkey.go). Since Not Configured already
			// means "never" for that one key, Disabled instead maps onto
			// "user-decides" there, so it stays reachable as an explicit,
			// GPO-settable override.
			policy.ValueName = string(p.Key)
			policy.EnabledValue = &valueElem{String: strPtr(ptype.AlwaysByPolicy.String())}
			if p.Key == pkey.EnableDNSRegistration {
				policy.DisabledValue = &valueElem{String: strPtr(ptype.ShowChoiceByPolicy.String())}
			} else {
				policy.DisabledValue = &valueElem{String: strPtr(ptype.NeverByPolicy.String())}
			}
		case setting.VisibilityValue:
			policy.ValueName = string(p.Key)
			policy.EnabledValue = &valueElem{String: strPtr(ptype.VisibleByPolicy.String())}
			policy.DisabledValue = &valueElem{String: strPtr(ptype.HiddenByPolicy.String())}
		default:
			return nil, fmt.Errorf("policy %q has unsupported type %v for ADMX generation", p.Key, p.Type)
		}
		defs.Policies.Policy = append(defs.Policies.Policy, policy)
	}
	if p, err := buildBundleIfWindowsSupported(byKey, []pkey.Key{pkey.AlwaysOn, pkey.AlwaysOnOverrideWithReason}, buildAlwaysOnPolicy); err != nil {
		return nil, err
	} else if p != nil {
		defs.Policies.Policy = append(defs.Policies.Policy, *p)
	}
	if p, err := buildBundleIfWindowsSupported(byKey, []pkey.Key{pkey.ExitNodeID, pkey.AllowExitNodeOverride}, buildExitNodeIDPolicy); err != nil {
		return nil, err
	} else if p != nil {
		defs.Policies.Policy = append(defs.Policies.Policy, *p)
	}
	if p, err := buildBundleIfWindowsSupported(byKey, []pkey.Key{pkey.ManagedByOrganizationName, pkey.ManagedByCaption, pkey.ManagedByURL}, buildManagedByPolicy); err != nil {
		return nil, err
	} else if p != nil {
		defs.Policies.Policy = append(defs.Policies.Policy, *p)
	}

	body, err := xml.MarshalIndent(defs, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling ADMX XML: %w", err)
	}
	out := make([]byte, 0, len(xml.Header)+len(body)+1)
	out = append(out, []byte(xml.Header)...)
	out = append(out, body...)
	out = append(out, '\n')
	return out, nil
}
