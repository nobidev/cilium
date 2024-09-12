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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestLBServiceStatusVIP(t *testing.T) {
	r := lbServiceReconciler{}

	conditionType := "lb.cilium.io/VIPExist"

	testCases := []struct {
		desc                   string
		lbsvc                  *isovalentv1alpha1.LBService
		vip                    *isovalentv1alpha1.LBVIP
		expectedNrOfConditions int
		expectedStatus         metav1.ConditionStatus
		expectedReason         string
		expectedMessage        string
	}{
		{
			desc:                   "VIP exists",
			lbsvc:                  &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{VIPRef: isovalentv1alpha1.LBServiceVIPRef{Name: "my-vip"}}},
			vip:                    &isovalentv1alpha1.LBVIP{},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "VIPExists",
			expectedMessage:        "Referenced VIP exist",
		},
		{
			desc:                   "Missing VIP",
			lbsvc:                  &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{VIPRef: isovalentv1alpha1.LBServiceVIPRef{Name: "my-vip"}}},
			vip:                    nil,
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionFalse,
			expectedReason:         "VIPMissing",
			expectedMessage:        "Referenced VIP my-vip is missing",
		},
		{
			desc: "Update existing condition",
			lbsvc: &isovalentv1alpha1.LBService{
				Spec:   isovalentv1alpha1.LBServiceSpec{VIPRef: isovalentv1alpha1.LBServiceVIPRef{Name: "my-vip"}},
				Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"}}},
			},
			vip:                    &isovalentv1alpha1.LBVIP{},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "VIPExists",
			expectedMessage:        "Referenced VIP exist",
		},
		{
			desc: "Doesn't delete other conditions",
			lbsvc: &isovalentv1alpha1.LBService{Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{
				{Type: "other-type", Status: metav1.ConditionTrue, Reason: "other-reason", Message: "other-message"},
				{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"},
			}}},
			vip:                    &isovalentv1alpha1.LBVIP{},
			expectedNrOfConditions: 2,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "VIPExists",
			expectedMessage:        "Referenced VIP exist",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			r.updateVIPInStatus(tc.lbsvc, tc.vip)

			assert.Equal(t, tc.expectedNrOfConditions, len(tc.lbsvc.Status.Conditions))

			c := tc.lbsvc.GetStatusCondition(conditionType)
			require.NotNil(t, c)
			assert.Equal(t, tc.expectedStatus, c.Status)
			assert.Equal(t, tc.expectedReason, c.Reason)
			assert.Equal(t, tc.expectedMessage, c.Message)
		})
	}
}

func TestLBServiceStatusAssignedIP(t *testing.T) {
	r := lbServiceReconciler{}

	conditionType := "lb.cilium.io/IPAssigned"

	testCases := []struct {
		desc                   string
		model                  *lbService
		lbsvc                  *isovalentv1alpha1.LBService
		expectedNrOfConditions int
		expectedStatus         metav1.ConditionStatus
		expectedReason         string
		expectedMessage        string
	}{
		{
			desc:                   "IP pending",
			model:                  &lbService{vip: lbVIP{}},
			lbsvc:                  &isovalentv1alpha1.LBService{},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionFalse,
			expectedReason:         "IPPending",
			expectedMessage:        "VIP pending",
		},
		{
			desc:                   "IP pending",
			model:                  &lbService{vip: lbVIP{assignedIPv4: ptr.To("100.64.0.1")}},
			lbsvc:                  &isovalentv1alpha1.LBService{},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "IPAssigned",
			expectedMessage:        "VIP assigned",
		},
		{
			desc: "Failed to bind ip",
			model: &lbService{vip: lbVIP{bindStatus: lbVIPBindStatus{
				serviceExists:  true,
				bindSuccessful: false,
				bindIssue:      "not possible to bind",
			}}},
			lbsvc:                  &isovalentv1alpha1.LBService{},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionFalse,
			expectedReason:         "IPFailure",
			expectedMessage:        "Failed to bind to VIP: not possible to bind",
		},
		{
			desc:  "Update existing condition",
			model: &lbService{vip: lbVIP{assignedIPv4: ptr.To("100.64.0.1")}},
			lbsvc: &isovalentv1alpha1.LBService{Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{
				{Type: conditionType, Status: metav1.ConditionFalse, Reason: "reason", Message: "message"},
			}}},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "IPAssigned",
			expectedMessage:        "VIP assigned",
		},
		{
			desc:  "Doesn't delete other conditions",
			model: &lbService{vip: lbVIP{assignedIPv4: ptr.To("100.64.0.1")}},
			lbsvc: &isovalentv1alpha1.LBService{Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{
				{Type: "other-type", Status: metav1.ConditionFalse, Reason: "other-reason", Message: "other-message"},
				{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"},
			}}},
			expectedNrOfConditions: 2,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "IPAssigned",
			expectedMessage:        "VIP assigned",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			r.updateAssignedIpInStatus(tc.model, tc.lbsvc)

			assert.Equal(t, tc.expectedNrOfConditions, len(tc.lbsvc.Status.Conditions))

			c := tc.lbsvc.GetStatusCondition(conditionType)
			require.NotNil(t, c)
			assert.Equal(t, tc.expectedStatus, c.Status)
			assert.Equal(t, tc.expectedReason, c.Reason)
			assert.Equal(t, tc.expectedMessage, c.Message)
		})
	}
}

func TestLBServiceStatusSecret(t *testing.T) {
	r := lbServiceReconciler{}

	conditionType := "lb.cilium.io/SecretsExist"

	testCases := []struct {
		desc                   string
		lbsvc                  *isovalentv1alpha1.LBService
		missingSecrets         []string
		expectedNrOfConditions int
		expectedStatus         metav1.ConditionStatus
		expectedReason         string
		expectedMessage        string
	}{
		{
			desc:                   "All secrets exist",
			lbsvc:                  &isovalentv1alpha1.LBService{},
			missingSecrets:         []string{},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllSecretsExist",
			expectedMessage:        "All referenced TLS secrets exist",
		},
		{
			desc:                   "Missing secrets",
			lbsvc:                  &isovalentv1alpha1.LBService{},
			missingSecrets:         []string{"missing-secret", "another-missing-secret"},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionFalse,
			expectedReason:         "MissingSecrets",
			expectedMessage:        "There are referenced TLS secrets that do not exist: [missing-secret another-missing-secret]",
		},
		{
			desc:                   "Update existing condition",
			lbsvc:                  &isovalentv1alpha1.LBService{Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"}}}},
			missingSecrets:         []string{},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllSecretsExist",
			expectedMessage:        "All referenced TLS secrets exist",
		},
		{
			desc: "Doesn't delete other conditions",
			lbsvc: &isovalentv1alpha1.LBService{Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{
				{Type: "other-type", Status: metav1.ConditionTrue, Reason: "other-reason", Message: "other-message"},
				{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"},
			}}},
			missingSecrets:         []string{},
			expectedNrOfConditions: 2,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllSecretsExist",
			expectedMessage:        "All referenced TLS secrets exist",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			r.updateSecretsInStatus(tc.lbsvc, tc.missingSecrets)

			assert.Equal(t, tc.expectedNrOfConditions, len(tc.lbsvc.Status.Conditions))

			c := tc.lbsvc.GetStatusCondition(conditionType)
			require.NotNil(t, c)
			assert.Equal(t, tc.expectedStatus, c.Status)
			assert.Equal(t, tc.expectedReason, c.Reason)
			assert.Equal(t, tc.expectedMessage, c.Message)
		})
	}
}

func TestLBServiceStatusBackendExistence(t *testing.T) {
	r := lbServiceReconciler{}

	conditionType := "lb.cilium.io/BackendsExist"

	testCases := []struct {
		desc                   string
		lbsvc                  *isovalentv1alpha1.LBService
		missingBackends        []string
		expectedNrOfConditions int
		expectedStatus         metav1.ConditionStatus
		expectedReason         string
		expectedMessage        string
	}{
		{
			desc:                   "All backends exist",
			lbsvc:                  &isovalentv1alpha1.LBService{},
			missingBackends:        []string{},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllBackendsExist",
			expectedMessage:        "All referenced backends exist",
		},
		{
			desc:                   "Missing backends",
			lbsvc:                  &isovalentv1alpha1.LBService{},
			missingBackends:        []string{"missing-backend", "another-missing-backend"},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionFalse,
			expectedReason:         "MissingBackends",
			expectedMessage:        "There are referenced backends that do not exist: [missing-backend another-missing-backend]",
		},
		{
			desc:                   "Update existing condition",
			lbsvc:                  &isovalentv1alpha1.LBService{Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"}}}},
			missingBackends:        []string{},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllBackendsExist",
			expectedMessage:        "All referenced backends exist",
		},
		{
			desc: "Doesn't delete other conditions",
			lbsvc: &isovalentv1alpha1.LBService{Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{
				{Type: "other-type", Status: metav1.ConditionTrue, Reason: "other-reason", Message: "other-message"},
				{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"},
			}}},
			missingBackends:        []string{},
			expectedNrOfConditions: 2,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllBackendsExist",
			expectedMessage:        "All referenced backends exist",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			r.updateBackendExistenceInStatus(tc.lbsvc, tc.missingBackends)

			assert.Equal(t, tc.expectedNrOfConditions, len(tc.lbsvc.Status.Conditions))

			c := tc.lbsvc.GetStatusCondition(conditionType)
			require.NotNil(t, c)
			assert.Equal(t, tc.expectedStatus, c.Status)
			assert.Equal(t, tc.expectedReason, c.Reason)
			assert.Equal(t, tc.expectedMessage, c.Message)
		})
	}
}

func TestLBServiceStatusBackendCompatibility(t *testing.T) {
	r := lbServiceReconciler{}

	conditionType := "lb.cilium.io/BackendsCompatible"

	testCases := []struct {
		desc                   string
		lbsvc                  *isovalentv1alpha1.LBService
		backends               []*isovalentv1alpha1.LBBackendPool
		expectedNrOfConditions int
		expectedStatus         metav1.ConditionStatus
		expectedReason         string
		expectedMessage        string
	}{
		{
			desc: "All backends compatible (no persistent backends)",
			lbsvc: &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{Applications: isovalentv1alpha1.LBServiceApplications{
				HTTPProxy: &isovalentv1alpha1.LBServiceApplicationHTTPProxy{
					Routes: []isovalentv1alpha1.LBServiceHTTPRoute{{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}}},
				},
				HTTPSProxy: &isovalentv1alpha1.LBServiceApplicationHTTPSProxy{
					Routes: []isovalentv1alpha1.LBServiceHTTPRoute{{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}}},
				},
				TLSPassthrough: &isovalentv1alpha1.LBServiceApplicationTLSPassthrough{
					Routes: []isovalentv1alpha1.LBServiceTLSPassthroughRoute{{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}}},
				},
				TLSProxy: &isovalentv1alpha1.LBServiceApplicationTLSProxy{
					Routes: []isovalentv1alpha1.LBServiceTLSRoute{{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}}},
				},
			}}},
			backends: []*isovalentv1alpha1.LBBackendPool{
				{ObjectMeta: metav1.ObjectMeta{Name: "backend-1"}, Spec: isovalentv1alpha1.LBBackendPoolSpec{}},
			},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllBackendsCompatible",
			expectedMessage:        "All referenced backends are compatible",
		},
		{
			desc: "All backends compatible (with persistent backends)",
			lbsvc: &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{Applications: isovalentv1alpha1.LBServiceApplications{
				HTTPProxy: &isovalentv1alpha1.LBServiceApplicationHTTPProxy{
					Routes: []isovalentv1alpha1.LBServiceHTTPRoute{
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-2"}, PersistentBackend: &isovalentv1alpha1.LBServiceHTTPRoutePersistentBackend{}},
					},
				},
				HTTPSProxy: &isovalentv1alpha1.LBServiceApplicationHTTPSProxy{
					Routes: []isovalentv1alpha1.LBServiceHTTPRoute{
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-2"}, PersistentBackend: &isovalentv1alpha1.LBServiceHTTPRoutePersistentBackend{}},
					},
				},
				TLSPassthrough: &isovalentv1alpha1.LBServiceApplicationTLSPassthrough{
					Routes: []isovalentv1alpha1.LBServiceTLSPassthroughRoute{
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-2"}, PersistentBackend: &isovalentv1alpha1.LBServiceTLSRoutePersistentBackend{}},
					},
				},
				TLSProxy: &isovalentv1alpha1.LBServiceApplicationTLSProxy{
					Routes: []isovalentv1alpha1.LBServiceTLSRoute{
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-2"}, PersistentBackend: &isovalentv1alpha1.LBServiceTLSRoutePersistentBackend{}},
					},
				},
			}}},
			backends: []*isovalentv1alpha1.LBBackendPool{
				{ObjectMeta: metav1.ObjectMeta{Name: "backend-1"}, Spec: isovalentv1alpha1.LBBackendPoolSpec{}},
				{ObjectMeta: metav1.ObjectMeta{Name: "backend-2"}, Spec: isovalentv1alpha1.LBBackendPoolSpec{Loadbalancing: &isovalentv1alpha1.Loadbalancing{Algorithm: isovalentv1alpha1.LoadbalancingAlgorithm{ConsistentHashing: &isovalentv1alpha1.LoadbalancingAlgorithmConsistentHashing{}}}}},
			},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllBackendsCompatible",
			expectedMessage:        "All referenced backends are compatible",
		},
		{
			desc: "Incompatible backends (persistent backend selection but no consistent hashing)",
			lbsvc: &isovalentv1alpha1.LBService{Spec: isovalentv1alpha1.LBServiceSpec{Applications: isovalentv1alpha1.LBServiceApplications{
				HTTPProxy: &isovalentv1alpha1.LBServiceApplicationHTTPProxy{
					Routes: []isovalentv1alpha1.LBServiceHTTPRoute{
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-2"}, PersistentBackend: &isovalentv1alpha1.LBServiceHTTPRoutePersistentBackend{}},
					},
				},
				HTTPSProxy: &isovalentv1alpha1.LBServiceApplicationHTTPSProxy{
					Routes: []isovalentv1alpha1.LBServiceHTTPRoute{
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-2"}, PersistentBackend: &isovalentv1alpha1.LBServiceHTTPRoutePersistentBackend{}},
					},
				},
				TLSPassthrough: &isovalentv1alpha1.LBServiceApplicationTLSPassthrough{
					Routes: []isovalentv1alpha1.LBServiceTLSPassthroughRoute{
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-2"}, PersistentBackend: &isovalentv1alpha1.LBServiceTLSRoutePersistentBackend{}},
					},
				},
				TLSProxy: &isovalentv1alpha1.LBServiceApplicationTLSProxy{
					Routes: []isovalentv1alpha1.LBServiceTLSRoute{
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
						{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-2"}, PersistentBackend: &isovalentv1alpha1.LBServiceTLSRoutePersistentBackend{}},
					},
				},
			}}},
			backends: []*isovalentv1alpha1.LBBackendPool{
				{ObjectMeta: metav1.ObjectMeta{Name: "backend-1"}, Spec: isovalentv1alpha1.LBBackendPoolSpec{}},
				{ObjectMeta: metav1.ObjectMeta{Name: "backend-2"}, Spec: isovalentv1alpha1.LBBackendPoolSpec{Loadbalancing: &isovalentv1alpha1.Loadbalancing{Algorithm: isovalentv1alpha1.LoadbalancingAlgorithm{RoundRobin: &isovalentv1alpha1.LoadbalancingAlgorithmRoundRobin{}}}}},
			},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionFalse,
			expectedReason:         "IncompatibleBackends",
			expectedMessage:        `Backend "backend-2" is incompatible: Configured "persistentBackend" without LB algorithm "consistentHashing"`,
		},
		{
			desc: "Update existing condition",
			lbsvc: &isovalentv1alpha1.LBService{
				Spec: isovalentv1alpha1.LBServiceSpec{Applications: isovalentv1alpha1.LBServiceApplications{
					HTTPProxy: &isovalentv1alpha1.LBServiceApplicationHTTPProxy{
						Routes: []isovalentv1alpha1.LBServiceHTTPRoute{
							{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
						},
					},
				}},
				Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"}}},
			},
			backends: []*isovalentv1alpha1.LBBackendPool{
				{ObjectMeta: metav1.ObjectMeta{Name: "backend-1"}, Spec: isovalentv1alpha1.LBBackendPoolSpec{}},
			},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllBackendsCompatible",
			expectedMessage:        "All referenced backends are compatible",
		},
		{
			desc: "Doesn't delete other conditions",
			lbsvc: &isovalentv1alpha1.LBService{
				Spec: isovalentv1alpha1.LBServiceSpec{Applications: isovalentv1alpha1.LBServiceApplications{
					HTTPProxy: &isovalentv1alpha1.LBServiceApplicationHTTPProxy{
						Routes: []isovalentv1alpha1.LBServiceHTTPRoute{
							{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
						},
					},
				}},
				Status: isovalentv1alpha1.LBServiceStatus{Conditions: []metav1.Condition{
					{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"},
					{Type: "other-type", Status: metav1.ConditionTrue, Reason: "other-reason", Message: "other-message"},
				}},
			},
			backends: []*isovalentv1alpha1.LBBackendPool{
				{ObjectMeta: metav1.ObjectMeta{Name: "backend-1"}, Spec: isovalentv1alpha1.LBBackendPoolSpec{}},
			},
			expectedNrOfConditions: 2,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "AllBackendsCompatible",
			expectedMessage:        "All referenced backends are compatible",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			r.updateBackendCompatibilityInStatus(tc.lbsvc, tc.backends)

			assert.Equal(t, tc.expectedNrOfConditions, len(tc.lbsvc.Status.Conditions))

			c := tc.lbsvc.GetStatusCondition(conditionType)
			require.NotNil(t, c)
			assert.Equal(t, tc.expectedStatus, c.Status)
			assert.Equal(t, tc.expectedReason, c.Reason)
			assert.Equal(t, tc.expectedMessage, c.Message)
		})
	}
}
