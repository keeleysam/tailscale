// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package policydoc provides human-readable labels and descriptions for
// Tailscale system policies, for use by documentation generators such as
// cmd/genpolicydocs. It is intentionally separate from [setting.Definition],
// which governs runtime policy validation: nothing in this package affects
// how policies are read or applied.
package policydoc

import "tailscale.com/util/syspolicy/pkey"

// Category names, the verbatim H3 section headings (in order) at
// https://tailscale.com/docs/features/tailscale-system-policies, so that
// page's taxonomy is the single source of truth for how policies are
// grouped, reused by every generator (the Windows ADMX category tree, the
// iOS/tvOS AppConfig field groups) instead of each format inventing its own.
const (
	CategoryAutoUpdate   = "Configure the auto-update settings"
	CategoryExitNode     = "Configure the exit node settings"
	CategoryOrganization = "Show contact information for your organization"
	CategoryRuntime      = "Other settings"
	CategoryUIVisibility = "Change the visibility of UI items"
)

// Entry is the label, description, and category for one policy key, sourced
// primarily from https://tailscale.com/kb/1315/mdm-keys,
// https://tailscale.com/docs/features/tailscale-system-policies, and
// docs/windows/policy/en-US/tailscale.adml.
type Entry struct {
	Key         pkey.Key
	Label       string
	Description string
	// Category is one of the Category* constants above. Keys not listed on
	// the system-policies doc page are assigned the category their nature
	// most closely matches (e.g. ExitNodeIP alongside its sibling ExitNodeID).
	Category string
}

// Entries holds one Entry for every policy key currently registered via
// [setting.Definitions]. Keep this in sync as new keys are added to
// util/syspolicy/policy_keys.go: TestPolicydocCoversAllDefinitions enforces it.
var Entries = []Entry{
	{Key: pkey.AllowedSuggestedExitNodes, Label: "Allowed suggested exit nodes", Description: "Restrict, by device ID, which exit nodes Tailscale may automatically select and enforce as the suggested exit node when a forced exit node is set to \"auto:any\". The suggested exit node is shown in the GUI and CLI. If left empty, all available exit nodes may be suggested. See https://tailscale.com/kb/1315/mdm-keys#suggest-allowed-forced-exit-nodes and https://tailscale.com/kb/1103/exit-nodes for details.", Category: CategoryExitNode},
	{Key: pkey.AllowExitNodeOverride, Label: "Allow exit node override", Description: "Allow the user to override exit node policy settings and manually select a different exit node, without allowing them to disable exit node usage entirely. Typically used together with a forced exit node set to \"auto:any\".", Category: CategoryExitNode},
	{Key: pkey.AllowTailscaledRestart, Label: "Allow users to restart tailscaled", Description: "Control whether users are allowed to fully reset the connection by restarting tailscaled. This can be useful for troubleshooting certain connectivity issues.", Category: CategoryRuntime},
	{Key: pkey.AlwaysOn, Label: "Always On", Description: "Prevent the user from disconnecting from the tailnet or exiting the client. Often combined with unattended mode to keep the device connected regardless of whether a user is logged in, useful for remote access or for ensuring connectivity to internal infrastructure before a user logs in.", Category: CategoryRuntime},
	{Key: pkey.AlwaysOnOverrideWithReason, Label: "Require reason to override Always On", Description: "When Always On is enabled, require the user to submit a reason to override and disconnect.", Category: CategoryRuntime},
	{Key: pkey.ApplyUpdates, Label: "Automatically install updates", Description: "Control whether updates are automatically installed once downloaded. See https://tailscale.com/kb/1067/update#auto-updates for details.", Category: CategoryAutoUpdate},
	{Key: pkey.AuthKey, Label: "Auth key", Description: "Auth key used to authenticate this device without user interaction, for unattended registration, unless the device is already logged in or a different auth key is specified via the CLI. Delivering secrets through policy mechanisms carries real risk: policy values are often readable by other users and applications on the device, and a leaked auth key can be used to gain or elevate access to the tailnet. Only use this after reviewing your organization's security posture: scope the auth key to a specific tag with tight ACLs, prefer short-lived or one-time keys, and consider Device Approval and Tailnet Lock to reduce risk. Revoke the auth key immediately if it may have been compromised. See https://tailscale.com/kb/1315/mdm-keys#set-an-auth-key for details.", Category: CategoryRuntime},
	{Key: pkey.CheckUpdates, Label: "Automatically check for updates", Description: "Control whether the Tailscale client periodically checks for updates. See https://tailscale.com/docs/features/client/update for details.", Category: CategoryAutoUpdate},
	{Key: pkey.ControlURL, Label: "Coordination server URL", Description: "Require using a specific Tailscale coordination server. Set to the URL of the coordination server, beginning with https:// and no trailing slash. If left blank, the default Tailscale coordination server is used. See https://tailscale.com/kb/1315/mdm-keys#set-a-custom-control-server-url for details.", Category: CategoryRuntime},
	{Key: pkey.DeviceSerialNumber, Label: "Device serial number", Description: "Provide the device's serial number. Mobile platforms (Android, iOS, tvOS) cannot read their own serial number due to sandboxing, so MDM must supply it here for serial-based device attribution.", Category: CategoryRuntime},
	{Key: pkey.EnableDNSRegistration, Label: "Register Tailscale IP addresses in DNS", Description: "Control whether Tailscale IP addresses are registered in DNS and whether dynamic DNS updates are enabled for the Tailscale interface. Registering addresses is recommended in enterprise DNS environments where internal infrastructure, including domain controllers, is reachable over Tailscale. Unlike most policies here, the Disabled state does not force registration off: it leaves the choice to Tailscale's own default, which is already off when this policy is left Not Configured.", Category: CategoryRuntime},
	{Key: pkey.EnableIncomingConnections, Label: "Allow incoming connections", Description: "Control whether the device accepts incoming connections from other tailnet devices. See https://tailscale.com/kb/1315/mdm-keys#set-whether-to-allow-incoming-connections and https://tailscale.com/kb/1072/client-preferences#allow-incoming-connections for details.", Category: CategoryRuntime},
	{Key: pkey.EnableRunExitNode, Label: "Run Tailscale as an exit node", Description: "Control whether the device advertises itself as an exit node. The device must still be approved by a tailnet administrator before it can be used as one. See https://tailscale.com/kb/1103/exit-nodes for details.", Category: CategoryExitNode},
	{Key: pkey.EnableServerMode, Label: "Run Tailscale in unattended mode", Description: "Control whether Tailscale keeps running and connected without requiring a user to be logged in. See https://tailscale.com/kb/1315/mdm-keys#set-unattended-mode and https://tailscale.com/kb/1088/run-unattended for details.", Category: CategoryRuntime},
	{Key: pkey.EnableTailscaleDNS, Label: "Use Tailscale DNS settings", Description: "Control whether Tailscale applies its DNS configuration while the tunnel is connected. See https://tailscale.com/kb/1315/mdm-keys#set-whether-the-device-uses-tailscale-dns-settings for details.", Category: CategoryRuntime},
	{Key: pkey.EnableTailscaleSubnets, Label: "Use Tailscale subnets", Description: "Control whether the client accepts subnet routes advertised by other nodes in the tailnet. See https://tailscale.com/kb/1315/mdm-keys#set-whether-the-device-accepts-tailscale-subnets and https://tailscale.com/kb/1019/subnets for details.", Category: CategoryRuntime},
	{Key: pkey.ExitNodeAllowLANAccess, Label: "Allow LAN access while using an exit node", Description: "Control whether the device can still reach the local network while using an exit node. See https://tailscale.com/kb/1315/mdm-keys#toggle-local-network-access-when-an-exit-node-is-in-use and https://tailscale.com/kb/1103/exit-nodes#step-4-use-the-exit-node for details.", Category: CategoryExitNode},
	{Key: pkey.ExitNodeID, Label: "Forced exit node", Description: "Force the client to always use the given exit node. Set to an exit node's ID, visible on the Machines page of the admin console or via the Tailscale API, or to \"auto:any\" to let Tailscale automatically select the most suitable exit node. If the specified exit node becomes unavailable, the device has no internet access unless Tailscale is disconnected. Leave unset to let the user choose an exit node themselves, if one is available and permitted by ACLs. See https://tailscale.com/kb/1315/mdm-keys#force-an-exit-node-to-always-be-used and https://tailscale.com/kb/1103/exit-nodes for details.", Category: CategoryExitNode},
	{Key: pkey.ExitNodeIP, Label: "Forced exit node (by IP)", Description: "Force the client to always use the exit node with the given IP address. Prefer the exit node ID where possible; it takes precedence if both are set.", Category: CategoryExitNode},
	{Key: pkey.FlushDNSOnSessionUnlock, Label: "Flush the DNS cache on session unlock", Description: "Flush the DNS cache on session unlock, in addition to when it would normally be flushed. Intended for debugging; only enable if recommended by Tailscale Support.", Category: CategoryRuntime},
	{Key: pkey.EncryptState, Label: "Encrypt client state file stored on disk", Description: "Encrypt the Tailscale client state file on disk using a hardware-backed key (TPM on Windows/Linux, Keychain on Apple platforms) where available. If no such hardware-backed key is available, Tailscale will fail to start.", Category: CategoryRuntime},
	{Key: pkey.Hostname, Label: "Hostname override", Description: "Override the hostname reported to the coordination server, instead of using the device's OS-configured hostname.", Category: CategoryRuntime},
	{Key: pkey.LogSCMInteractions, Label: "Log extra details about service events", Description: "Enable additional logging related to the Windows Service Control Manager, for debugging purposes. Only enable if recommended by Tailscale Support.", Category: CategoryRuntime},
	{Key: pkey.LogTarget, Label: "Log server URL", Description: "Require using a specific, non-standard log server. Using a non-standard log server limits Tailscale Support's ability to diagnose problems.", Category: CategoryRuntime},
	{Key: pkey.MachineCertificateSubject, Label: "Machine certificate subject", Description: "The exact Subject that must be present in an identity's certificate chain to sign a device registration request, formatted per pkix.Name.String().", Category: CategoryRuntime},
	{Key: pkey.PostureChecking, Label: "Posture checking", Description: "Control whether the client gathers device posture data for posture-based access rules. See https://tailscale.com/kb/1315/mdm-keys#enable-gathering-device-posture-data and https://tailscale.com/kb/1326/device-identity for details.", Category: CategoryRuntime},
	{Key: pkey.ReconnectAfter, Label: "Automatic reconnect delay", Description: "How long Tailscale waits before automatically reconnecting after a user disconnects it. Specify as a Go duration (e.g. 30s, 5m, 1h30m). Leave blank or zero to disable automatic reconnection. See https://pkg.go.dev/time#ParseDuration for details.", Category: CategoryRuntime},
	{Key: pkey.Tailnet, Label: "Suggested or required tailnet", Description: "Suggest or require a specific tailnet at login. Provide the tailnet name, as shown in the top-left of the admin console (e.g. \"example.com\"), or prefix it with \"required:\" to require it rather than merely suggest it. When suggested rather than required, that tailnet's SSO button is shown prominently on the login page, alongside the option to choose a different tailnet. See https://tailscale.com/kb/1315/mdm-keys#set-a-suggested-or-required-tailnet for details.", Category: CategoryRuntime},
	{Key: pkey.HardwareAttestation, Label: "Hardware attestation", Description: "Control whether to use a hardware-backed key to bind the node's identity to this specific device.", Category: CategoryRuntime},
	{Key: pkey.AdminConsoleVisibility, Label: "Show admin console access", Description: "Show or hide the option to open the tailnet admin console from the client.", Category: CategoryUIVisibility},
	{Key: pkey.AutoUpdateVisibility, Label: "Show automatic-update menu item", Description: "Show or hide the menu item controlling automatic installation of updates.", Category: CategoryAutoUpdate},
	{Key: pkey.ExitNodeMenuVisibility, Label: "Show exit node picker", Description: "Show or hide the exit node picker UI in the Tailscale client. This doesn't affect selecting or stopping exit node usage via the CLI. See https://tailscale.com/kb/1315/mdm-keys#hide-the-exit-node-picker for details.", Category: CategoryUIVisibility},
	{Key: pkey.KeyExpirationNoticeTime, Label: "Key expiration notice", Description: "How long before node key expiry to show the user a notice. Uses Go duration format, e.g. \"24h\" or \"5h25m30s\". Defaults to 24 hours if left unset. See https://tailscale.com/kb/1315/mdm-keys#set-the-key-expiration-notice-period for details.", Category: CategoryRuntime},
	{Key: pkey.ManagedByCaption, Label: "Managed-by caption", Description: "Support caption text shown alongside the managed-by organization name.", Category: CategoryOrganization},
	{Key: pkey.ManagedByOrganizationName, Label: "Managed-by organization name", Description: "Name of the organization managing this device, shown in the client as \"Managed By {Organization}\".", Category: CategoryOrganization},
	{Key: pkey.ManagedByURL, Label: "Managed-by support URL", Description: "URL to a help desk or support resource for users in the organization, shown in the client.", Category: CategoryOrganization},
	{Key: pkey.NetworkDevicesVisibility, Label: "Show network devices submenu", Description: "Show or hide the submenu listing other devices on the tailnet. This doesn't affect other devices' visibility via the CLI.", Category: CategoryUIVisibility},
	{Key: pkey.PreferencesMenuVisibility, Label: "Show preferences submenu", Description: "Show or hide the client's preferences/settings submenu. This doesn't affect changing those preferences via the CLI. See https://tailscale.com/kb/1315/mdm-keys#hide-the-preferences-menu for details.", Category: CategoryUIVisibility},
	{Key: pkey.ResetToDefaultsVisibility, Label: "Show reset-to-defaults option", Description: "Show or hide the option to reset client preferences back to their defaults.", Category: CategoryUIVisibility},
	{Key: pkey.RunExitNodeVisibility, Label: "Show run-exit-node option", Description: "Show or hide the menu item for running this device as an exit node, without affecting the underlying setting itself. See https://tailscale.com/kb/1315/mdm-keys#hide-the-run-as-exit-node-menu-item for details.", Category: CategoryUIVisibility},
	{Key: pkey.SuggestedExitNodeVisibility, Label: "Show suggested exit nodes", Description: "Control the visibility of automatic exit node suggestions. When hidden, no exit node suggestion is presented to the user in the exit node picker.", Category: CategoryUIVisibility},
	{Key: pkey.TestMenuVisibility, Label: "Show debug submenu", Description: "Show or hide the client's debug/test submenu. See https://tailscale.com/kb/1315/mdm-keys#hide-the-debug-menu for details.", Category: CategoryUIVisibility},
	{Key: pkey.UpdateMenuVisibility, Label: "Show update notification", Description: "Show or hide the update-available notification in the client. See https://tailscale.com/kb/1315/mdm-keys#hide-the-update-menu for details.", Category: CategoryUIVisibility},
	{Key: pkey.OnboardingFlowVisibility, Label: "Show onboarding flow", Description: "Show or hide the first-run onboarding flow for users who haven't yet signed in.", Category: CategoryUIVisibility},
}
