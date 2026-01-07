//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	"net"
	"net/netip"
	"testing"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/policy/api"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"

	"github.com/cilium/hive/hivetest"

	"github.com/stretchr/testify/assert"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

func parseNetIPs(t *testing.T, ss ...string) []netip.Addr {
	out := []netip.Addr{}
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func Test_computeHealthyGateways(t *testing.T) {
	policyHealthyGatewayIPs := []gatewayNodeIP{
		{
			ip:                    netip.MustParseAddr("10.0.0.1"),
			selectingGroupIndices: []int{0},
			zone:                  true,
			available:             true,
		},
		{
			ip:                    netip.MustParseAddr("10.0.0.2"),
			selectingGroupIndices: []int{3, 2, 1},
			zone:                  true,
			available:             true,
		},
		{
			ip:                    netip.MustParseAddr("10.0.0.3"),
			selectingGroupIndices: []int{},
			zone:                  true,
			available:             false,
		},
		{
			ip:                    netip.MustParseAddr("10.0.0.4"),
			selectingGroupIndices: []int{3, 2, 0},
			zone:                  false,
			available:             true,
		},
	}
	assert.Equal(t, parseNetIPs(t,
		"10.0.0.1", "10.0.0.4"), computeHealthyGateways(policyHealthyGatewayIPs, false, 0))

}

func Test_computeAvailableHealthyGatewaysByAZ(t *testing.T) {
	policyHealthyGatewayIPs := map[string][]gatewayNodeIP{
		"az-0": {
			{
				ip:                    netip.MustParseAddr("10.0.0.1"),
				selectingGroupIndices: []int{0},
				zone:                  true,
				available:             true,
			},
			{
				ip:                    netip.MustParseAddr("10.0.0.2"),
				selectingGroupIndices: []int{3, 2, 1},
				zone:                  true,
				available:             true,
			},
			{
				ip:                    netip.MustParseAddr("10.0.0.3"),
				selectingGroupIndices: []int{},
				zone:                  true,
				available:             true,
			},
			{
				ip:                    netip.MustParseAddr("10.0.0.4"),
				selectingGroupIndices: []int{3, 2, 0},
				zone:                  false,
				available:             true,
			},
		},
		"az-1": {
			{
				ip:                    netip.MustParseAddr("10.0.0.5"),
				selectingGroupIndices: []int{0, 2, 3},
				zone:                  false,
				available:             true,
			},
		},
	}
	out := computeAvailableHealthyGatewaysByAZ(policyHealthyGatewayIPs, false, 0)
	assert.Equal(t, map[string][]netip.Addr{
		"az-0": parseNetIPs(t, "10.0.0.1", "10.0.0.4"),
		"az-1": parseNetIPs(t, "10.0.0.5"),
	}, out)
	out = computeAvailableHealthyGatewaysByAZ(policyHealthyGatewayIPs, true, 0)
	assert.Equal(t, map[string][]netip.Addr{
		"az-0": parseNetIPs(t, "10.0.0.1"),
		"az-1": {},
	}, out)
}

func Test_preComputePolicyHealthyGatewaysWithAZAffinity(t *testing.T) {
	tests := []struct {
		name           string
		nodes          []nodeTypes.Node
		policyConfig   *PolicyConfig
		expectedAZKeys []string
		expectedGWs    map[azAffinityMode]map[string][]gatewayNodeIP
	}{
		{
			name: "basic multiple groups with overlapping and distinct selectors",
			nodes: []nodeTypes.Node{
				{
					Labels: map[string]string{
						"foo":                     "bar",
						core_v1.LabelTopologyZone: "a",
					},
					IPAddresses: []nodeTypes.Address{
						{
							Type: addressing.NodeInternalIP,
							IP:   net.IP{10, 0, 0, 1},
						},
					},
				},
				{
					Labels: map[string]string{
						"x":                       "y",
						core_v1.LabelTopologyZone: "b",
					},
					IPAddresses: []nodeTypes.Address{
						{
							Type: addressing.NodeInternalIP,
							IP:   net.IP{10, 0, 0, 2},
						},
					},
				},
				{
					Labels: map[string]string{
						"match":                   "none",
						core_v1.LabelTopologyZone: "c",
					},
					IPAddresses: []nodeTypes.Address{
						{
							Type: addressing.NodeInternalIP,
							IP:   net.IP{10, 0, 0, 3},
						},
					},
				},
			},
			policyConfig: &PolicyConfig{
				id:  types.NamespacedName{Name: "p0", Namespace: "default"},
				uid: "0",
				groupConfigs: []groupConfig{
					{
						nodeSelector: policyTypes.NewLabelSelector(api.EndpointSelector{
							LabelSelector: &slimv1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						}),
					},
					{
						nodeSelector: policyTypes.NewLabelSelector(api.EndpointSelector{
							LabelSelector: &slimv1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						}),
					},
					{
						nodeSelector: policyTypes.NewLabelSelector(api.EndpointSelector{
							LabelSelector: &slimv1.LabelSelector{
								MatchLabels: map[string]string{"x": "y"},
							},
						}),
					},
				},
			},
			expectedGWs: map[azAffinityMode]map[string][]gatewayNodeIP{
				azAffinityDisabled: {
					"0": {
						{
							ip:                    netip.MustParseAddr("10.0.0.1"),
							selectingGroupIndices: []int{0, 1}, // selected multiple times by first two groupConfigs.
							zone:                  true,
							available:             true,
						},
						{
							ip:                    netip.MustParseAddr("10.0.0.2"),
							selectingGroupIndices: []int{2}, // only selected by last groupConfig.
							zone:                  true,
							available:             true,
						},
					},
				},
				azAffinityLocalOnly: {
					"a": {
						{
							ip:                    netip.MustParseAddr("10.0.0.1"),
							selectingGroupIndices: []int{0, 1},
							available:             true,
							zone:                  true,
						},
					},
					"b": {
						{
							ip:                    netip.MustParseAddr("10.0.0.2"),
							selectingGroupIndices: []int{2},
							available:             true,
							zone:                  true,
						},
					},
					"c": {},
				},
			},
		},
		{
			name:  "empty nodes list",
			nodes: []nodeTypes.Node{},
			policyConfig: &PolicyConfig{
				id:  types.NamespacedName{Name: "p1", Namespace: "default"},
				uid: "1",

				groupConfigs: []groupConfig{
					{
						nodeSelector: policyTypes.NewLabelSelector(api.EndpointSelector{
							LabelSelector: &slimv1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						}),
					},
				},
			},
			expectedGWs: map[azAffinityMode]map[string][]gatewayNodeIP{
				azAffinityDisabled:  {},
				azAffinityLocalOnly: {},
			},
		},
		{
			name: "no matching nodes",
			nodes: []nodeTypes.Node{
				{
					Labels: map[string]string{
						"match":                   "none",
						core_v1.LabelTopologyZone: "a",
					},
					IPAddresses: []nodeTypes.Address{
						{
							Type: addressing.NodeInternalIP,
							IP:   net.IP{10, 0, 0, 1},
						},
					},
				},
			},
			policyConfig: &PolicyConfig{
				id:  types.NamespacedName{Name: "p2", Namespace: "default"},
				uid: "0",
				groupConfigs: []groupConfig{
					{
						nodeSelector: policyTypes.NewLabelSelector(api.EndpointSelector{
							LabelSelector: &slimv1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						}),
					},
				},
			},
			expectedGWs: map[azAffinityMode]map[string][]gatewayNodeIP{
				azAffinityDisabled: {
					"0": {},
				},
				azAffinityLocalOnly: {
					"a": {},
				},
			},
		},
		{
			name: "node with no internal IP address should not be added to output",
			nodes: []nodeTypes.Node{
				{
					Labels: map[string]string{
						"foo":                     "bar",
						core_v1.LabelTopologyZone: "a",
					},
					IPAddresses: []nodeTypes.Address{
						{
							Type: addressing.NodeCiliumInternalIP,
							IP:   net.IP{10, 0, 10, 1},
						},
					},
				},
			},
			policyConfig: &PolicyConfig{
				id:  types.NamespacedName{Name: "p3", Namespace: "default"},
				uid: "1",
				groupConfigs: []groupConfig{
					{
						nodeSelector: policyTypes.NewLabelSelector(api.EndpointSelector{
							LabelSelector: &slimv1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						}),
					},
				},
			},
			expectedGWs: map[azAffinityMode]map[string][]gatewayNodeIP{
				azAffinityDisabled: {
					"1": {},
				},
				azAffinityLocalOnly: {
					"a": {},
				},
			},
		},
		{
			name: "single node matching all groups",
			nodes: []nodeTypes.Node{
				{
					Labels: map[string]string{
						"foo":                     "bar",
						"x":                       "y",
						"z":                       "w",
						core_v1.LabelTopologyZone: "x",
					},
					IPAddresses: []nodeTypes.Address{
						{
							Type: addressing.NodeInternalIP,
							IP:   net.IP{10, 0, 0, 1},
						},
					},
				},
			},
			policyConfig: &PolicyConfig{
				id:  types.NamespacedName{Name: "p5", Namespace: "default"},
				uid: "5",
				groupConfigs: []groupConfig{
					{
						nodeSelector: policyTypes.NewLabelSelector(api.EndpointSelector{
							LabelSelector: &slimv1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						}),
					},
					{
						nodeSelector: policyTypes.NewLabelSelector(api.EndpointSelector{
							LabelSelector: &slimv1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						}),
					},
					{
						nodeSelector: policyTypes.NewLabelSelector(api.EndpointSelector{
							LabelSelector: &slimv1.LabelSelector{
								MatchLabels: map[string]string{"z": "w"},
							},
						}),
					},
				},
			},
			expectedGWs: map[azAffinityMode]map[string][]gatewayNodeIP{
				azAffinityDisabled: {
					"5": {
						{
							ip:                    netip.MustParseAddr("10.0.0.1"),
							selectingGroupIndices: []int{0, 1, 2},
							available:             true,
							zone:                  true,
						},
					},
				},
				azAffinityLocalOnly: {
					"x": {
						{
							ip:                    netip.MustParseAddr("10.0.0.1"),
							selectingGroupIndices: []int{0, 1, 2},
							available:             true,
							zone:                  true,
						},
					},
				},
			},
		},
		{
			name: "empty group configs",
			nodes: []nodeTypes.Node{
				{
					Labels: map[string]string{
						"foo":                     "bar",
						core_v1.LabelTopologyZone: "x",
					},
					IPAddresses: []nodeTypes.Address{
						{
							Type: addressing.NodeInternalIP,
							IP:   net.IP{10, 0, 0, 1},
						},
					},
				},
			},
			policyConfig: &PolicyConfig{
				id:           types.NamespacedName{Name: "p6", Namespace: "default"},
				uid:          "000",
				groupConfigs: []groupConfig{},
			},
			expectedGWs: map[azAffinityMode]map[string][]gatewayNodeIP{
				azAffinityDisabled: {
					"000": {},
				},
				azAffinityLocalOnly: {
					"x": {},
				},
			},
		},
		{
			name: "nodes with nil labels",
			nodes: []nodeTypes.Node{
				{
					Labels: nil,
					IPAddresses: []nodeTypes.Address{
						{
							Type: addressing.NodeInternalIP,
							IP:   net.IP{10, 0, 0, 1},
						},
					},
				},
			},
			policyConfig: &PolicyConfig{
				id:  types.NamespacedName{Name: "p7", Namespace: "default"},
				uid: "000",
				groupConfigs: []groupConfig{
					{
						nodeSelector: policyTypes.NewLabelSelector(api.EndpointSelector{
							LabelSelector: &slimv1.LabelSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						}),
					},
				},
			},
			expectedGWs: map[azAffinityMode]map[string][]gatewayNodeIP{
				azAffinityDisabled: {
					"000": {},
				},
				azAffinityLocalOnly: {},
			},
		},
		// TODO: Re-enable when you figure out empty selector behavior:
		/*{
			name: "selector with nil LabelSelector",
			nodes: []nodeTypes.Node{
				{
					Labels: map[string]string{
						"foo":                     "bar",
						core_v1.LabelTopologyZone: "x",
					},
					IPAddresses: []nodeTypes.Address{
						{
							Type: addressing.NodeInternalIP,
							IP:   net.IP{10, 0, 0, 1},
						},
					},
				},
			},
			policyConfig: &PolicyConfig{
				id:  types.NamespacedName{Name: "p10", Namespace: "default"},
				uid: "0",
				groupConfigs: []groupConfig{
					{
						nodeSelector: api.EndpointSelector{
							LabelSelector: nil,
						},
					},
				},
			},
			expectedGWs: map[azAffinityMode]map[string][]gatewayNodeIP{
				azAffinityDisabled: map[string][]gatewayNodeIP{
					"0": {},
				},
				azAffinityLocalOnly: map[string][]gatewayNodeIP{
					"x": {},
				},
			},
		},*/
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &OperatorManager{
				logger:        hivetest.Logger(t),
				nodes:         tt.nodes,
				healthchecker: &mockHealthChecker{},
			}

			for _, mode := range []azAffinityMode{azAffinityDisabled, azAffinityLocalOnly} {
				tt.policyConfig.azAffinity = mode
				nToAZ := nodeToAZFn(tt.policyConfig.azAffinity, tt.policyConfig.uid)
				_, availByAZ := tt.policyConfig.preComputePolicyHealthyGateways(m, nToAZ)
				assert.Equal(t, tt.expectedGWs[mode], availByAZ, "Gateway mappings mismatch")
			}
		})
	}
}
