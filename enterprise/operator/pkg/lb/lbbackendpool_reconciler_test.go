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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestLBBackendPoolStatusAccepted(t *testing.T) {
	r := lbBackendPoolReconciler{}

	conditionType := "lb.cilium.io/Accepted"

	testCases := []struct {
		desc                   string
		lbbp                   *isovalentv1alpha1.LBBackendPool
		expectedNrOfConditions int
		expectedStatus         metav1.ConditionStatus
		expectedReason         string
		expectedMessage        string
	}{
		{
			desc:                   "Valid",
			lbbp:                   &isovalentv1alpha1.LBBackendPool{Spec: isovalentv1alpha1.LBBackendPoolSpec{}},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "Valid",
			expectedMessage:        "BackendPool is valid and accepted",
		},
		{
			desc: "Valid maglev table size",
			lbbp: &isovalentv1alpha1.LBBackendPool{Spec: isovalentv1alpha1.LBBackendPoolSpec{Loadbalancing: &isovalentv1alpha1.Loadbalancing{Algorithm: isovalentv1alpha1.LoadbalancingAlgorithm{
				ConsistentHashing: &isovalentv1alpha1.LoadbalancingAlgorithmConsistentHashing{Algorithm: &isovalentv1alpha1.LoadbalancingConsistentHashingAlgorithm{Maglev: isovalentv1alpha1.LoadbalancingConsistentHashingAlgorithmMaglev{TableSize: ptr.To[uint32](3)}}},
			}}}},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "Valid",
			expectedMessage:        "BackendPool is valid and accepted",
		},
		{
			desc: "Invalid maglev table size",
			lbbp: &isovalentv1alpha1.LBBackendPool{Spec: isovalentv1alpha1.LBBackendPoolSpec{Loadbalancing: &isovalentv1alpha1.Loadbalancing{Algorithm: isovalentv1alpha1.LoadbalancingAlgorithm{
				ConsistentHashing: &isovalentv1alpha1.LoadbalancingAlgorithmConsistentHashing{Algorithm: &isovalentv1alpha1.LoadbalancingConsistentHashingAlgorithm{Maglev: isovalentv1alpha1.LoadbalancingConsistentHashingAlgorithmMaglev{TableSize: ptr.To[uint32](10)}}},
			}}}},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionFalse,
			expectedReason:         "Invalid",
			expectedMessage:        "BackendPool is invalid: .spec.loadBalancing.algorithm.consistentHashing.algorithm.maglev.tableSize 10 is not prime",
		},
		{
			desc: "Update existing condition",
			lbbp: &isovalentv1alpha1.LBBackendPool{
				Spec:   isovalentv1alpha1.LBBackendPoolSpec{},
				Status: isovalentv1alpha1.LBBackendPoolStatus{Conditions: []metav1.Condition{{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"}}},
			},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "Valid",
			expectedMessage:        "BackendPool is valid and accepted",
		},
		{
			desc: "Doesn't delete other conditions",
			lbbp: &isovalentv1alpha1.LBBackendPool{Status: isovalentv1alpha1.LBBackendPoolStatus{Conditions: []metav1.Condition{
				{Type: "other-type", Status: metav1.ConditionTrue, Reason: "other-reason", Message: "other-message"},
				{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"},
			}}},
			expectedNrOfConditions: 2,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "Valid",
			expectedMessage:        "BackendPool is valid and accepted",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			r.updateAcceptedStatusCondition(tc.lbbp, []*corev1.Service{}, []string{})

			assert.Len(t, tc.lbbp.Status.Conditions, tc.expectedNrOfConditions)

			c := tc.lbbp.GetStatusCondition(conditionType)
			require.NotNil(t, c)
			assert.Equal(t, tc.expectedStatus, c.Status)
			assert.Equal(t, tc.expectedReason, c.Reason)
			assert.Equal(t, tc.expectedMessage, c.Message)
		})
	}
}
