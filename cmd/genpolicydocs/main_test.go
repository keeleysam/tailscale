// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import "testing"

func TestRepoRootFromSubdirectory(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("repoRoot() from repo root: %v", err)
	}

	// Simulate how go:generate invokes this command: cwd is the directory of
	// the file containing the //go:generate directive
	// (util/syspolicy/policy_keys.go), not the repo root.
	t.Chdir("../../util/syspolicy")

	gotFromSubdir, err := repoRoot()
	if err != nil {
		t.Fatalf("repoRoot() from util/syspolicy: %v", err)
	}
	if gotFromSubdir != root {
		t.Errorf("repoRoot() from util/syspolicy = %q, want %q (same as from repo root)", gotFromSubdir, root)
	}
}
