// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package securitygroups

import (
	"strconv"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	privnetTypes "github.com/cilium/cilium/enterprise/pkg/privnet/types"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
)

func TestSecurityGroupReflectorTransform(t *testing.T) {
	tests := []struct {
		name         string
		obj          *v1alpha1.FabricSecurityGroup
		expectLabels labels.LabelArray
		expectErr    bool
	}{
		{
			name: "valid object",
			obj: &v1alpha1.FabricSecurityGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "123"},
				Spec: v1alpha1.FabricSecurityGroupSpec{
					EndpointSelector: &slimv1.LabelSelector{
						MatchLabels: map[string]string{
							"role":                                   "db",
							"k8s:io.kubernetes.pod.namespace":        "default",
							"cni:com.isovalent.private-network.name": "red",
						},
					},
				},
			},
			expectLabels: labels.LabelArray{
				labels.NewLabel("role", "db", labels.LabelSourceK8s),
				labels.NewLabel(ciliumio.PodNamespaceLabel, "default", labels.LabelSourceK8s),
				labels.NewLabel(privnetTypes.CNINetworkNameLabel, "red", labels.LabelSourceCNI),
			},
		},
		{
			name: "valid object with no selector",
			obj: &v1alpha1.FabricSecurityGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "456"},
			},
		},
		{
			name:      "reject unnamed object",
			obj:       &v1alpha1.FabricSecurityGroup{},
			expectErr: true,
		},
		{
			name: "reject non-numeric name",
			obj: &v1alpha1.FabricSecurityGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "not-a-number"},
			},
			expectErr: true,
		},
		{
			name: "reject out-of-range numeric name",
			obj: &v1alpha1.FabricSecurityGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "65536"},
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &securityGroups{log: hivetest.Logger(t)}

			transformed, ok := r.transform(tt.obj)
			if tt.expectErr {
				require.False(t, ok)
				return
			}
			require.True(t, ok)

			expectedID, err := strconv.ParseUint(tt.obj.GetName(), 10, 16)
			require.NoError(t, err)
			require.Equal(t, uint16(expectedID), transformed.GroupID)

			if tt.obj.Spec.EndpointSelector != nil {
				require.NotNil(t, transformed.EndpointSelector)
				require.True(t, transformed.EndpointSelector.Matches(tt.expectLabels),
					"expected labels (%s) do not match the transformed selector (%s)",
					tt.expectLabels, transformed.EndpointSelector.String())
			}
		})
	}
}
