// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"testing"

	"github.com/stretchr/testify/require"

	ciliumMetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestMatchT1Node(t *testing.T) {
	testCases := []struct {
		name     string
		selector *ciliumMetav1.LabelSelector
		expected bool
	}{
		{
			name:     "nil selector",
			selector: nil,
			expected: false,
		},
		{
			name: "matchLabels t1",
			selector: &ciliumMetav1.LabelSelector{
				MatchLabels: map[string]string{
					"service.cilium.io/node": "t1",
				},
			},
			expected: true,
		},
		{
			name: "matchLabels t1-t2",
			selector: &ciliumMetav1.LabelSelector{
				MatchLabels: map[string]string{
					"service.cilium.io/node": "t1-t2",
				},
			},
			expected: true,
		},
		{
			name: "matchLabels t2",
			selector: &ciliumMetav1.LabelSelector{
				MatchLabels: map[string]string{
					"service.cilium.io/node": "t2",
				},
			},
			expected: false,
		},
		{
			name: "matchExpressions in t1",
			selector: &ciliumMetav1.LabelSelector{
				MatchExpressions: []ciliumMetav1.LabelSelectorRequirement{
					{
						Key:      "service.cilium.io/node",
						Operator: ciliumMetav1.LabelSelectorOpIn,
						Values:   []string{"t1"},
					},
				},
			},
			expected: true,
		},
		{
			name: "matchExpressions in t2",
			selector: &ciliumMetav1.LabelSelector{
				MatchExpressions: []ciliumMetav1.LabelSelectorRequirement{
					{
						Key:      "service.cilium.io/node",
						Operator: ciliumMetav1.LabelSelectorOpIn,
						Values:   []string{"t2"},
					},
				},
			},
			expected: false,
		},
		{
			name: "matchExpressions notin t1",
			selector: &ciliumMetav1.LabelSelector{
				MatchExpressions: []ciliumMetav1.LabelSelectorRequirement{
					{
						Key:      "service.cilium.io/node",
						Operator: ciliumMetav1.LabelSelectorOpNotIn,
						Values:   []string{"t1"},
					},
				},
			},
			expected: false,
		},
		{
			name: "matchExpressions in t1 with extra constraints",
			selector: &ciliumMetav1.LabelSelector{
				MatchExpressions: []ciliumMetav1.LabelSelectorRequirement{
					{
						Key:      "service.cilium.io/node",
						Operator: ciliumMetav1.LabelSelectorOpIn,
						Values:   []string{"t1"},
					},
					{
						Key:      "topology.kubernetes.io/zone",
						Operator: ciliumMetav1.LabelSelectorOpIn,
						Values:   []string{"dal"},
					},
				},
			},
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, matchT1Node(tc.selector))
		})
	}
}
