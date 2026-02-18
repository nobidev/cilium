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
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/mac"
)

func TestExtractNetworkAttachmentAnnotation(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		want        *types.NetworkAttachment
		wantErr     string
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
			want: &types.NetworkAttachment{
				Network: "blue",
				IPv4:    netip.MustParseAddr("192.168.1.10"),
				IPv6:    netip.MustParseAddr("fd10::10"),
				MAC:     mac.MustParseMAC("f2:54:1c:1f:84:94"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			na, err := types.ExtractNetworkAttachmentAnnotation(&metav1.ObjectMeta{Annotations: tt.annotations})

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr, "ExtractNetworkAttachmentAnnotation")
			} else {
				require.NoError(t, err, "ExtractNetworkAttachmentAnnotation")
			}

			require.Equal(t, tt.want, na)
		})
	}
}
