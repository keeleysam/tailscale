// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/xml"
	"fmt"
	"slices"

	"tailscale.com/util/syspolicy/ptype"
	"tailscale.com/util/syspolicy/setting"
)

type managedAppConfiguration struct {
	XMLName      xml.Name         `xml:"managedAppConfiguration"`
	Version      int              `xml:"version"`
	BundleID     string           `xml:"bundleId"`
	Dict         appConfigDict    `xml:"dict"`
	Presentation presentationElem `xml:"presentation"`
}

type appConfigDict struct {
	Strings      []stringKeyElem      `xml:"string"`
	StringArrays []stringArrayKeyElem `xml:"stringArray"`
	Booleans     []booleanKeyElem     `xml:"boolean"`
}

type stringKeyElem struct {
	KeyName    string          `xml:"keyName,attr"`
	Default    *valueWrapElem  `xml:"defaultValue"`
	Constraint *constraintElem `xml:"constraint,omitempty"`
}

type stringArrayKeyElem struct {
	KeyName string `xml:"keyName,attr"`
}

type booleanKeyElem struct {
	KeyName string         `xml:"keyName,attr"`
	Default *valueWrapElem `xml:"defaultValue"`
}

type valueWrapElem struct {
	Value string `xml:"value"`
}

type constraintElem struct {
	Values valuesListElem `xml:"values"`
}

type valuesListElem struct {
	Value []string `xml:"value"`
}

type presentationElem struct {
	DefaultLocale string       `xml:"defaultLocale,attr"`
	FieldGroups   []fieldGroup `xml:"fieldGroup"`
}

type fieldGroup struct {
	Name   nameElem `xml:"name"`
	Fields []field  `xml:"field"`
}

type nameElem struct {
	Language languageElem `xml:"language"`
}

type languageElem struct {
	Locale string `xml:"value,attr"`
	Text   string `xml:",chardata"`
}

type field struct {
	KeyName     string       `xml:"keyName,attr"`
	Type        string       `xml:"type,attr"`
	Label       *labelElem   `xml:"label,omitempty"`
	Description *descElem    `xml:"description,omitempty"`
	Options     *optionsElem `xml:"options,omitempty"`
}

type labelElem struct {
	Language languageElem `xml:"language"`
}

type descElem struct {
	Language languageElem `xml:"language"`
}

type optionsElem struct {
	Option []optionElem `xml:"option"`
}

type optionElem struct {
	Value    string       `xml:"value,attr"`
	Selected bool         `xml:"selected,attr,omitempty"`
	Language languageElem `xml:"language"`
}

// renderAppConfig builds an AppConfig spec XML document containing every
// policy in policies that supports the given platform (an OS name matching
// [setting.PlatformList.Has]'s convention, e.g. "iOS" or "tvOS"), declared
// under the given bundleID.
func renderAppConfig(policies []policyInfo, platform, bundleID string) ([]byte, error) {
	mac := managedAppConfiguration{
		Version:  1,
		BundleID: bundleID,
	}
	fieldsByCategory := make(map[string][]field, len(categoryOrder))
	for _, p := range policies {
		if !p.Platforms.Has(platform) {
			continue
		}
		f := field{
			KeyName:     string(p.Key),
			Label:       &labelElem{Language: languageElem{Locale: "en", Text: p.Label}},
			Description: &descElem{Language: languageElem{Locale: "en", Text: p.Description}},
		}
		switch p.Type {
		case setting.BooleanValue:
			f.Type = "checkbox"
			mac.Dict.Booleans = append(mac.Dict.Booleans, booleanKeyElem{
				KeyName: string(p.Key),
				Default: &valueWrapElem{Value: "false"},
			})
		case setting.StringValue, setting.DurationValue:
			f.Type = "input"
			mac.Dict.Strings = append(mac.Dict.Strings, stringKeyElem{
				KeyName: string(p.Key),
				Default: &valueWrapElem{Value: ""},
			})
		case setting.StringListValue:
			f.Type = "list"
			mac.Dict.StringArrays = append(mac.Dict.StringArrays, stringArrayKeyElem{
				KeyName: string(p.Key),
			})
		case setting.PreferenceOptionValue:
			always, never, userDecides := ptype.AlwaysByPolicy.String(), ptype.NeverByPolicy.String(), ptype.ShowChoiceByPolicy.String()
			f.Type = "select"
			f.Options = &optionsElem{Option: []optionElem{
				{Value: "", Selected: true, Language: languageElem{Locale: "en", Text: "Not configured"}},
				{Value: always, Language: languageElem{Locale: "en", Text: "Always"}},
				{Value: never, Language: languageElem{Locale: "en", Text: "Never"}},
				{Value: userDecides, Language: languageElem{Locale: "en", Text: "User decides"}},
			}}
			mac.Dict.Strings = append(mac.Dict.Strings, stringKeyElem{
				KeyName: string(p.Key),
				Default: &valueWrapElem{Value: ""},
				Constraint: &constraintElem{Values: valuesListElem{
					Value: []string{"", always, never, userDecides},
				}},
			})
		case setting.VisibilityValue:
			show, hide := ptype.VisibleByPolicy.String(), ptype.HiddenByPolicy.String()
			f.Type = "select"
			f.Options = &optionsElem{Option: []optionElem{
				{Value: "", Selected: true, Language: languageElem{Locale: "en", Text: "Not configured"}},
				{Value: show, Language: languageElem{Locale: "en", Text: "Show"}},
				{Value: hide, Language: languageElem{Locale: "en", Text: "Hide"}},
			}}
			mac.Dict.Strings = append(mac.Dict.Strings, stringKeyElem{
				KeyName: string(p.Key),
				Default: &valueWrapElem{Value: ""},
				Constraint: &constraintElem{Values: valuesListElem{
					Value: []string{"", show, hide},
				}},
			})
		default:
			return nil, fmt.Errorf("policy %q has unsupported type %v for AppConfig generation", p.Key, p.Type)
		}
		if !slices.Contains(categoryOrder, p.Category) {
			return nil, fmt.Errorf("policy %q has unknown category %q", p.Key, p.Category)
		}
		fieldsByCategory[p.Category] = append(fieldsByCategory[p.Category], f)
	}
	var groups []fieldGroup
	for _, cat := range categoryOrder {
		fields := fieldsByCategory[cat]
		if len(fields) == 0 {
			continue
		}
		groups = append(groups, fieldGroup{
			Name:   nameElem{Language: languageElem{Locale: "en", Text: cat}},
			Fields: fields,
		})
	}
	mac.Presentation = presentationElem{
		DefaultLocale: "en",
		FieldGroups:   groups,
	}

	body, err := xml.MarshalIndent(mac, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling AppConfig XML: %w", err)
	}
	out := make([]byte, 0, len(xml.Header)+len(body)+1)
	out = append(out, []byte(xml.Header)...)
	out = append(out, body...)
	out = append(out, '\n')
	return out, nil
}
