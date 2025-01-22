/*
Copyright (C) Isovalent, Inc. - All Rights Reserved.

NOTICE: All information contained herein is, and remains the property of
Isovalent Inc and its suppliers, if any. The intellectual and technical
concepts contained herein are proprietary to Isovalent Inc and its suppliers
and may be covered by U.S. and Foreign Patents, patents in process, and are
protected by trade secret or copyright law.  Dissemination of this information
or reproduction of this material is strictly forbidden unless prior written
permission is obtained from Isovalent Inc.
*/

package helm

import (
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	ciliumiov1alpha1 "github.com/isovalent/cilium/enterprise/olm/api/cilium.io/v1alpha1"
)

func TestValues(t *testing.T) {
	ccfg := &ciliumiov1alpha1.CiliumConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "config",
			Namespace: "cilium",
		},
		Spec: ciliumiov1alpha1.CiliumConfigSpec{
			RawExtension: runtime.RawExtension{
				Raw: []byte(`{"securityContext": {"privileged": true}, "ipam":{"mode": "cluster-pool"}, "cni": {"binPath": "/var/lib/cni/bin", "confPath": "/var/run/multus/cni/net.d"}}`),
			},
		},
	}
	_, err := Values(ccfg)
	require.NoError(t, err, "expected no error getting helm values")
}

func TestInvalidValues(t *testing.T) {
	ccfg := &ciliumiov1alpha1.CiliumConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "config",
			Namespace: "cilium",
		},
		Spec: ciliumiov1alpha1.CiliumConfigSpec{
			RawExtension: runtime.RawExtension{
				Raw: []byte(`invalid`),
			},
		},
	}
	_, err := Values(ccfg)
	require.Error(t, err, "expected an error getting invalid helm values")
}
