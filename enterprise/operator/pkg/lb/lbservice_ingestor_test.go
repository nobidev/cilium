//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lb

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestHasSelectorBasedK8sServiceBackends(t *testing.T) {
	ing := &ingestor{}
	backends := []*isovalentv1alpha1.LBBackendPool{{
		ObjectMeta: metav1.ObjectMeta{Name: "pool"},
		Spec: isovalentv1alpha1.LBBackendPoolSpec{
			Backends: []isovalentv1alpha1.Backend{{
				K8sServiceRef: &isovalentv1alpha1.LBBackendPoolK8sServiceRef{Name: "webapp"},
				Port:          8080,
			}},
		},
	}}

	t.Run("selector based service enables integration", func(t *testing.T) {
		require.True(t, ing.hasSelectorBasedK8sServiceBackends(backends, []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "webapp"},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "webapp"},
			},
		}}))
	})

	t.Run("selectorless service keeps integration disabled", func(t *testing.T) {
		require.False(t, ing.hasSelectorBasedK8sServiceBackends(backends, []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "webapp"},
		}}))
	})
}
