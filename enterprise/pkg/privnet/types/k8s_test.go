//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package types_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/mac"
)

func TestExtractNetworkAttachmentAnnotation(t *testing.T) {
	tests := []struct {
		name          string
		annotations   map[string]string
		wantPrimary   *types.NetworkAttachment
		wantSecondary []types.NetworkAttachment
		wantErr       string
	}{
		{
			name: "missing",
		},
		{
			name:        "empty",
			annotations: map[string]string{types.PrivateNetworkAnnotation: ""},
			wantErr:     `invalid value in "privnet.isovalent.com/network-attachment" annotation: unexpected end of JSON input`,
		},
		{
			name:        "invalid",
			annotations: map[string]string{types.PrivateNetworkAnnotation: `{ foo^ }`},
			wantErr:     `invalid value in "privnet.isovalent.com/network-attachment" annotation: invalid character 'f'`,
		},
		{
			name: "primary",
			annotations: map[string]string{
				types.PrivateNetworkAnnotation: `{ "network": "blue", "ipv4": "192.168.1.10", "ipv6": "fd10::10", "mac": "f2:54:1c:1f:84:94" }`,
			},
			wantPrimary: &types.NetworkAttachment{
				Network: "blue",
				IPv4:    netip.MustParseAddr("192.168.1.10"),
				IPv6:    netip.MustParseAddr("fd10::10"),
				MAC:     mac.MustParseMAC("f2:54:1c:1f:84:94"),
			},
		},
		{
			name: "primary-with-interface",
			annotations: map[string]string{
				types.PrivateNetworkAnnotation: `{ "network": "blue", "ipv4": "192.168.1.10", "interface": "foo" }`,
			},
			wantPrimary: &types.NetworkAttachment{
				Network: "blue",
				IPv4:    netip.MustParseAddr("192.168.1.10"),
			},
		},
		{
			name: "primary+secondary",
			annotations: map[string]string{
				types.PrivateNetworkAnnotation: `{ "network": "blue", "ipv4": "192.168.1.10", "ipv6": "fd10::10", "mac": "f2:54:1c:1f:84:94" }`,
				types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
					{ "network": "green", "ipv4": "192.168.1.11", "ipv6": "fd10::11", "mac": "f2:54:1c:1f:84:95" },
					{ "network": "yellow", "ipv4": "192.168.1.12", "ipv6": "fd10::12", "mac": "f2:54:1c:1f:84:96" }
				]`,
			},
			wantPrimary: &types.NetworkAttachment{
				Network: "blue",
				IPv4:    netip.MustParseAddr("192.168.1.10"),
				IPv6:    netip.MustParseAddr("fd10::10"),
				MAC:     mac.MustParseMAC("f2:54:1c:1f:84:94"),
			},
			wantSecondary: []types.NetworkAttachment{{
				Network: "green",
				IPv4:    netip.MustParseAddr("192.168.1.11"),
				IPv6:    netip.MustParseAddr("fd10::11"),
				MAC:     mac.MustParseMAC("f2:54:1c:1f:84:95"),
			}, {
				Network: "yellow",
				IPv4:    netip.MustParseAddr("192.168.1.12"),
				IPv6:    netip.MustParseAddr("fd10::12"),
				MAC:     mac.MustParseMAC("f2:54:1c:1f:84:96"),
			}},
		},
		{
			name: "secondary-with-interface",
			annotations: map[string]string{
				types.PrivateNetworkAnnotation: `{ "network": "blue", "ipv4": "192.168.1.10" }`,
				types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
					{ "network": "green", "ipv4": "192.168.1.11", "interface": "foo" },
					{ "network": "yellow", "ipv4": "192.168.1.12", "interface": "bar" }
				]`,
			},
			wantPrimary: &types.NetworkAttachment{
				Network: "blue", IPv4: netip.MustParseAddr("192.168.1.10"),
			},
			wantSecondary: []types.NetworkAttachment{
				{Network: "green", IPv4: netip.MustParseAddr("192.168.1.11"), Interface: "foo"},
				{Network: "yellow", IPv4: netip.MustParseAddr("192.168.1.12"), Interface: "bar"},
			},
		},
		{
			name: "secondary-interface-mixed",
			annotations: map[string]string{
				types.PrivateNetworkAnnotation: `{ "network": "blue", "ipv4": "192.168.1.10" }`,
				types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
					{ "network": "green", "ipv4": "192.168.1.11", "interface": "foo" },
					{ "network": "yellow", "ipv4": "192.168.1.12" }
				]`,
			},
			wantErr: `interface must be specified for either none or all secondary attachments`,
		},
		{
			name: "secondary-only",
			annotations: map[string]string{types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
				{ "network": "green", "ipv4": "192.168.1.11", "ipv6": "fd10::11", "mac": "f2:54:1c:1f:84:95" }
			]`},
			wantSecondary: []types.NetworkAttachment{{
				Network: "green",
				IPv4:    netip.MustParseAddr("192.168.1.11"),
				IPv6:    netip.MustParseAddr("fd10::11"),
				MAC:     mac.MustParseMAC("f2:54:1c:1f:84:95"),
			}},
		},
		{
			name: "secondary-invalid",
			annotations: map[string]string{
				types.PrivateNetworkAnnotation: `{ "network": "blue", "ipv4": "192.168.1.10", "ipv6": "fd10::10" }`,
				types.PrivateNetworkSecondaryAttachmentsAnnotation: `[
					{ "network? }
				]`},
			wantErr: `invalid value in "privnet.isovalent.com/secondary-network-attachments" annotation: invalid character`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				obj             = metav1.ObjectMeta{Annotations: tt.annotations}
				primary, errp   = types.ExtractNetworkAttachmentAnnotation(&obj)
				secondary, errs = types.ExtractNetworkSecondaryAttachmentsAnnotation(&obj)
				err             = errors.Join(errp, errs)
			)

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr, "ExtractNetworkAttachmentAnnotation")
				return
			}

			require.NoError(t, err, "ExtractNetworkAttachmentAnnotation")
			require.Equal(t, tt.wantPrimary, primary)
			require.Equal(t, tt.wantSecondary, secondary)
		})
	}
}
