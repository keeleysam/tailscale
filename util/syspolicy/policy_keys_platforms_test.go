// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import (
	"slices"
	"testing"

	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/setting"
)

func TestPlatformRestrictedDefinitions(t *testing.T) {
	registerWellKnownSettingsForTest(t)
	tests := []struct {
		key  pkey.Key
		want []string // nil means unrestricted (supported everywhere)
	}{
		{pkey.EnableDNSRegistration, []string{"windows"}},
		{pkey.LogSCMInteractions, []string{"windows"}},
		{pkey.FlushDNSOnSessionUnlock, []string{"windows"}},
		{pkey.AutoUpdateVisibility, []string{"macOS"}},
		{pkey.DeviceSerialNumber, []string{"android", "iOS", "tvOS"}},
		{pkey.ControlURL, nil}, // unrestricted key stays unrestricted
		// Inert on iOS/tvOS/Android: EncryptState's state-encryption check
		// hardcodes true for those OSes without ever consulting the policy
		// (see LocalBackend.stateEncrypted), and HardwareAttestation's only
		// key-registration backend is TPM, registered for windows/linux
		// only (see feature/tpm.init).
		{pkey.EncryptState, []string{"windows", "macOS", "linux"}},
		{pkey.HardwareAttestation, []string{"windows", "linux"}},
		// Inert outside windows/macOS: control/controlclient/sign_supported.go
		// (the only reader of this policy) is built only under
		// windows || (darwin && !ios && cgo); sign_unsupported.go covers
		// everything else, including ios, and never reads the policy.
		{pkey.MachineCertificateSubject, []string{"windows", "macOS"}},
		// The KB's per-key platform table (kb/1315/mdm-keys) has no Linux
		// column at all, so none of these should carry "linux" without a
		// source to back it. See docs/windows/policy/README.md.
		{pkey.AdminConsoleVisibility, []string{"windows"}},
		{pkey.ExitNodeMenuVisibility, []string{"macOS", "iOS", "windows", "android"}},
		{pkey.NetworkDevicesVisibility, []string{"windows"}},
		{pkey.PreferencesMenuVisibility, []string{"windows"}},
		{pkey.ResetToDefaultsVisibility, []string{"macOS"}},
		{pkey.RunExitNodeVisibility, []string{"macOS", "tvOS", "windows", "android"}},
		{pkey.TestMenuVisibility, []string{"macOS", "windows"}},
		{pkey.UpdateMenuVisibility, []string{"windows", "macOS", "iOS"}},
		{pkey.OnboardingFlowVisibility, []string{"macOS", "windows", "android"}},
		// Never audited: stays at the universal default rather than being
		// guessed at, unlike its siblings above.
		{pkey.SuggestedExitNodeVisibility, nil},
	}
	defs, err := setting.Definitions()
	if err != nil {
		t.Fatalf("setting.Definitions() error: %v", err)
	}
	byKey := make(map[pkey.Key]*setting.Definition, len(defs))
	for _, d := range defs {
		byKey[d.Key()] = d
	}
	for _, tt := range tests {
		d, ok := byKey[tt.key]
		if !ok {
			t.Errorf("key %q not found in setting.Definitions()", tt.key)
			continue
		}
		got := slices.Clone([]string(d.SupportedPlatforms()))
		slices.Sort(got)
		want := slices.Clone(tt.want)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%q.SupportedPlatforms() = %v, want %v", tt.key, got, want)
		}
	}
}
