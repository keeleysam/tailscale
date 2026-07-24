// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The genpolicydocs command generates the iOS and tvOS AppConfig specs and
// the Windows ADMX/ADML policy templates from the policy definitions
// registered in util/syspolicy, joined with human-readable labels and
// descriptions from util/syspolicy/policydoc.
//
// Run it with: go run tailscale.com/cmd/genpolicydocs
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// repoRoot returns the absolute path of the tailscale.com module root, found
// by walking up from the current working directory until a go.mod is found.
// This lets the output paths below stay repo-root-relative regardless of
// whether this command is run directly (cwd is already the repo root) or via
// go:generate (cwd is the directory of the file containing the directive).
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod found above %q", dir)
		}
		dir = parent
	}
}

// appConfigTarget is one platform-specific AppConfig spec to generate.
type appConfigTarget struct {
	Platform   string // matches setting.PlatformList.Has's convention, e.g. "iOS"
	BundleID   string
	OutputPath string
}

// appConfigTargets lists every AppConfig spec this command generates. iOS
// and tvOS share a bundleID because Tailscale's tvOS app uses the same main
// bundle identifier as its iOS app; they're still separate output files
// because the two platforms support different subsets of policies.
var appConfigTargets = []appConfigTarget{
	{Platform: "iOS", BundleID: "io.tailscale.ipn.ios", OutputPath: "docs/ios/policy/tailscale.appconfig.xml"},
	{Platform: "tvOS", BundleID: "io.tailscale.ipn.ios", OutputPath: "docs/tvos/policy/tailscale.appconfig.xml"},
}

const (
	admxOutputPath = "docs/windows/policy/tailscale.admx"
	admlOutputPath = "docs/windows/policy/en-US/tailscale.adml"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "genpolicydocs:", err)
		os.Exit(1)
	}
}

func run() error {
	root, err := repoRoot()
	if err != nil {
		return fmt.Errorf("locating repo root: %w", err)
	}

	policies, err := loadPolicies()
	if err != nil {
		return fmt.Errorf("loading policies: %w", err)
	}
	for _, target := range appConfigTargets {
		appConfig, err := renderAppConfig(policies, target.Platform, target.BundleID)
		if err != nil {
			return fmt.Errorf("rendering %s AppConfig XML: %w", target.Platform, err)
		}
		if err := writeFile(filepath.Join(root, target.OutputPath), appConfig); err != nil {
			return err
		}
	}

	admx, err := renderADMX(policies)
	if err != nil {
		return fmt.Errorf("rendering ADMX XML: %w", err)
	}
	if err := writeFile(filepath.Join(root, admxOutputPath), admx); err != nil {
		return err
	}

	adml, err := renderADML(policies)
	if err != nil {
		return fmt.Errorf("rendering ADML XML: %w", err)
	}
	if err := writeFile(filepath.Join(root, admlOutputPath), adml); err != nil {
		return err
	}

	return nil
}

func writeFile(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating directory for %s: %w", path, err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
