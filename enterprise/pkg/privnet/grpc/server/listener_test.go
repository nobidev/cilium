//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package server

import (
	"fmt"
	"net"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	notypes "github.com/cilium/cilium/pkg/node/types"
)

// setNetListenForTest overrides the listen implementation and returns a restore func.
func setNetListenForTest(fn func(string, string) (net.Listener, error)) func() {
	orig := netListen
	netListen = fn
	return func() {
		netListen = orig
	}
}

func TestDefaultListenerFactory(t *testing.T) {
	tests := []struct {
		name      string
		addresses []notypes.Address
		expected  []string
		assertErr assert.ErrorAssertionFunc
	}{
		{
			name: "ipv4-only",
			addresses: []notypes.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.0.1")},
				{Type: addressing.NodeExternalIP, IP: net.ParseIP("10.255.0.1")},
			},
			expected:  []string{"10.0.0.1:1234"},
			assertErr: assert.NoError,
		},
		{
			name: "ipv6-only",
			addresses: []notypes.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("fd10::1")},
				{Type: addressing.NodeExternalIP, IP: net.ParseIP("fc10::1")},
			},
			expected:  []string{"[fd10::1]:1234"},
			assertErr: assert.NoError,
		},
		{
			name: "dual-stack",
			addresses: []notypes.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.0.1")},
				{Type: addressing.NodeExternalIP, IP: net.ParseIP("10.255.0.1")},
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("fd10::1")},
				{Type: addressing.NodeExternalIP, IP: net.ParseIP("fc10::1")},
			},
			expected:  []string{"10.0.0.1:1234", "[fd10::1]:1234"},
			assertErr: assert.NoError,
		},
		{
			name: "fallback",
			addresses: []notypes.Address{
				{Type: addressing.NodeExternalIP, IP: net.ParseIP("10.255.0.1")},
				{Type: addressing.NodeExternalIP, IP: net.ParseIP("fc10::1")},
			},
			expected:  []string{"10.255.0.1:1234", "[fc10::1]:1234"},
			assertErr: assert.NoError,
		},
		{
			name:      "missing",
			assertErr: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lns := node.NewTestLocalNodeStore(
				node.LocalNode{Node: notypes.Node{IPAddresses: tt.addresses}},
			)

			factory := NewListenerFactory(ListenerConfig{
				Port:          1234,
				Enabled:       true,
				AnnotationKey: types.PrivateNetworkINBAPIServerPortAnnotation,
			}, lns)

			restore := setNetListenForTest(func(network, address string) (net.Listener, error) {
				if network != "tcp" {
					return nil, fmt.Errorf("unexpected network protocol %q", network)
				}

				if !slices.Contains(tt.expected, address) {
					return nil, fmt.Errorf("unexpected address %q", address)
				}

				return &net.TCPListener{}, nil
			})
			defer restore()

			// Assert that the local node annotation is correctly set.
			ln, err := lns.Get(t.Context())
			require.NoError(t, err, "[lns.Get]")
			assert.Equal(t, "1234", ln.Annotations[types.PrivateNetworkINBAPIServerPortAnnotation])

			listeners, err := factory(t.Context())
			tt.assertErr(t, err)
			assert.Len(t, listeners, len(tt.expected))
		})
	}
}
