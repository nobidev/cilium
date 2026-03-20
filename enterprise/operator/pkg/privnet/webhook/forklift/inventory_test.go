// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package forklift

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/mac"
)

func TestVMInfoToInterfaces(t *testing.T) {
	var (
		mustAddr = netip.MustParseAddr
		mustMAC  = mac.MustParseMAC
	)

	tests := []struct {
		name          string
		build         vmInfo
		expected      []Interface
		errorContains string
	}{
		{
			name: "aggregates interfaces and ignores non-routable addresses",
			build: vmInfo{
				GuestNetworks: append([]vmGuestNetwork(nil),
					vmGuestNetwork{Device: "eth0", MAC: mustMAC("00:11:22:33:44:55"), IP: mustAddr("192.0.2.10")},
					vmGuestNetwork{Device: "eth0", MAC: mustMAC("00:11:22:33:44:55"), IP: mustAddr("2001:db8::10")},
					vmGuestNetwork{Device: "eth1", MAC: mustMAC("00:11:22:33:44:66"), IP: mustAddr("127.0.0.1") /* loopback */},
					vmGuestNetwork{Device: "eth2", MAC: mustMAC("00:11:22:33:44:77"), IP: mustAddr("198.51.100.20")},
					vmGuestNetwork{Device: "eth2", MAC: mustMAC("00:11:22:33:44:77"), IP: mustAddr("169.254.1.20") /* link local */},
					vmGuestNetwork{Device: "eth2", MAC: mustMAC("00:11:22:33:44:77"), IP: mustAddr("ff02::1") /* multicast */},
				),
			},
			expected: []Interface{
				{
					MAC:  mustMAC("00:11:22:33:44:55"),
					IPv4: mustAddr("192.0.2.10"),
					IPv6: mustAddr("2001:db8::10"),
				},
				{
					MAC: mustMAC("00:11:22:33:44:66"),
				},
				{
					MAC:  mustMAC("00:11:22:33:44:77"),
					IPv4: mustAddr("198.51.100.20"),
				},
			},
		},
		{
			name: "fails on mismatching MAC addresses",
			build: vmInfo{
				GuestNetworks: []vmGuestNetwork{
					{Device: "eth0", MAC: mustMAC("00:11:22:33:44:55"), IP: mustAddr("192.0.2.10")},
					{Device: "eth0", MAC: mustMAC("00:11:22:33:44:56"), IP: mustAddr("2001:db8::10")},
				},
			},
			errorContains: `mismatching MAC address for device "eth0"`,
		},
		{
			name: "fails on multiple global ipv4 addresses",
			build: vmInfo{
				GuestNetworks: []vmGuestNetwork{
					{Device: "eth0", MAC: mustMAC("00:11:22:33:44:55"), IP: mustAddr("192.0.2.10")},
					{Device: "eth0", MAC: mustMAC("00:11:22:33:44:55"), IP: mustAddr("198.51.100.10")},
				},
			},
			errorContains: `multiple global IPv4 addresses for device "eth0"`,
		},
		{
			name: "fails on multiple global ipv6 addresses",
			build: vmInfo{
				GuestNetworks: []vmGuestNetwork{
					{Device: "eth0", MAC: mustMAC("00:11:22:33:44:55"), IP: mustAddr("2001:db8::10")},
					{Device: "eth0", MAC: mustMAC("00:11:22:33:44:55"), IP: mustAddr("2001:db8::20")},
				},
			},
			errorContains: `multiple global IPv6 addresses for device "eth0"`,
		},
		{
			name: "fails when a device has no mac address",
			build: vmInfo{
				GuestNetworks: []vmGuestNetwork{
					{Device: "eth0", IP: mustAddr("192.0.2.10")},
				},
			},
			errorContains: `unknown MAC address for device "eth0"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ifaces, err := tt.build.toInterfaces()

			if tt.errorContains != "" {
				require.ErrorContains(t, err, tt.errorContains)
				return
			}

			require.NoError(t, err)
			require.ElementsMatch(t, tt.expected, ifaces)
		})
	}
}
