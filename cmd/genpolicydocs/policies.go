// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"sort"

	_ "tailscale.com/util/syspolicy" // registers policy definitions
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policydoc"
	"tailscale.com/util/syspolicy/setting"
)

// categoryOrder is the fixed display order for policydoc's Category*
// constants, matching the section order at
// https://tailscale.com/docs/features/tailscale-system-policies. Shared by
// every generator that groups policies by category (admx.go's category
// tree, appconfig.go's field groups) so they can't drift apart on ordering.
var categoryOrder = []string{
	policydoc.CategoryAutoUpdate,
	policydoc.CategoryExitNode,
	policydoc.CategoryOrganization,
	policydoc.CategoryRuntime,
	policydoc.CategoryUIVisibility,
}

// policyInfo joins a registered policy [setting.Definition] with its
// human-readable label and description from [policydoc.Entries].
type policyInfo struct {
	Key         pkey.Key
	Type        setting.Type
	Scope       setting.Scope
	Platforms   setting.PlatformList
	Label       string
	Description string
	Category    string
}

// loadPolicies returns every registered policy definition, joined with its
// policydoc.Entry, sorted by Key. It returns an error if any registered
// definition has no corresponding policydoc.Entry.
func loadPolicies() ([]policyInfo, error) {
	defs, err := setting.Definitions()
	if err != nil {
		return nil, fmt.Errorf("loading policy definitions: %w", err)
	}
	docsByKey := make(map[pkey.Key]policydoc.Entry, len(policydoc.Entries))
	for _, e := range policydoc.Entries {
		docsByKey[e.Key] = e
	}
	policies := make([]policyInfo, 0, len(defs))
	for _, d := range defs {
		doc, ok := docsByKey[d.Key()]
		if !ok {
			return nil, fmt.Errorf("no policydoc.Entry for key %q; add one to util/syspolicy/policydoc", d.Key())
		}
		policies = append(policies, policyInfo{
			Key:         d.Key(),
			Type:        d.Type(),
			Scope:       d.Scope(),
			Platforms:   d.SupportedPlatforms(),
			Label:       doc.Label,
			Description: doc.Description,
			Category:    doc.Category,
		})
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i].Key < policies[j].Key })
	return policies, nil
}
