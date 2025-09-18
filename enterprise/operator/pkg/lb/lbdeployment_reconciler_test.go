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

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestLBDeploymentStatusAccepted(t *testing.T) {
	r := lbDeploymentReconciler{}

	conditionType := "lb.cilium.io/Accepted"

	testCases := []struct {
		desc                   string
		lbd                    *isovalentv1alpha1.LBDeployment
		expectedNrOfConditions int
		expectedStatus         metav1.ConditionStatus
		expectedReason         string
		expectedMessage        string
	}{
		{
			desc: "Valid service & node labelselectors",
			lbd: &isovalentv1alpha1.LBDeployment{Spec: isovalentv1alpha1.LBDeploymentSpec{
				Services: isovalentv1alpha1.LBDeploymentServices{
					LabelSelector: &slim_metav1.LabelSelector{},
				},
				Nodes: isovalentv1alpha1.LBDeploymentNodes{
					LabelSelectors: &isovalentv1alpha1.LBDeploymentNodesLabelSelectors{
						T1: slim_metav1.LabelSelector{},
						T2: slim_metav1.LabelSelector{},
					},
				},
			}},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "Valid",
			expectedMessage:        "Deployment is valid and accepted",
		},
		{
			desc: "Invalid service labelselectors",
			lbd: &isovalentv1alpha1.LBDeployment{Spec: isovalentv1alpha1.LBDeploymentSpec{
				Services: isovalentv1alpha1.LBDeploymentServices{
					LabelSelector: &slim_metav1.LabelSelector{
						MatchExpressions: []slim_metav1.LabelSelectorRequirement{
							{
								Key:      "testlabel",
								Operator: slim_metav1.LabelSelectorOpIn,
								Values:   []string{},
							},
						},
						MatchLabels: map[string]slim_metav1.MatchLabelsValue{},
					},
				},
				Nodes: isovalentv1alpha1.LBDeploymentNodes{
					LabelSelectors: &isovalentv1alpha1.LBDeploymentNodesLabelSelectors{
						T1: slim_metav1.LabelSelector{},
						T2: slim_metav1.LabelSelector{},
					},
				},
			}},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionFalse,
			expectedReason:         "Invalid",
			expectedMessage:        "Deployment is invalid: Invalid service labelselector: values: Invalid value: []: for 'in', 'notin' operators, values set can't be empty",
		},
		{
			desc: "Invalid T1 node labelselectors",
			lbd: &isovalentv1alpha1.LBDeployment{Spec: isovalentv1alpha1.LBDeploymentSpec{
				Services: isovalentv1alpha1.LBDeploymentServices{
					LabelSelector: &slim_metav1.LabelSelector{},
				},
				Nodes: isovalentv1alpha1.LBDeploymentNodes{
					LabelSelectors: &isovalentv1alpha1.LBDeploymentNodesLabelSelectors{
						T1: slim_metav1.LabelSelector{
							MatchExpressions: []slim_metav1.LabelSelectorRequirement{
								{
									Key:      "testlabel",
									Operator: slim_metav1.LabelSelectorOpIn,
									Values:   []string{},
								},
							},
							MatchLabels: map[string]slim_metav1.MatchLabelsValue{},
						},
						T2: slim_metav1.LabelSelector{},
					},
				},
			}},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionFalse,
			expectedReason:         "Invalid",
			expectedMessage:        "Deployment is invalid: Invalid T1 node labelselector: values: Invalid value: []: for 'in', 'notin' operators, values set can't be empty",
		},
		{
			desc: "Invalid T2 node labelselectors",
			lbd: &isovalentv1alpha1.LBDeployment{Spec: isovalentv1alpha1.LBDeploymentSpec{
				Services: isovalentv1alpha1.LBDeploymentServices{
					LabelSelector: &slim_metav1.LabelSelector{},
				},
				Nodes: isovalentv1alpha1.LBDeploymentNodes{
					LabelSelectors: &isovalentv1alpha1.LBDeploymentNodesLabelSelectors{
						T1: slim_metav1.LabelSelector{},
						T2: slim_metav1.LabelSelector{
							MatchExpressions: []slim_metav1.LabelSelectorRequirement{
								{
									Key:      "testlabel",
									Operator: slim_metav1.LabelSelectorOpIn,
									Values:   []string{},
								},
							},
							MatchLabels: map[string]slim_metav1.MatchLabelsValue{},
						},
					},
				},
			}},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionFalse,
			expectedReason:         "Invalid",
			expectedMessage:        "Deployment is invalid: Invalid T2 node labelselector: values: Invalid value: []: for 'in', 'notin' operators, values set can't be empty",
		},
		{
			desc: "Update existing condition",
			lbd: &isovalentv1alpha1.LBDeployment{
				Spec: isovalentv1alpha1.LBDeploymentSpec{
					Services: isovalentv1alpha1.LBDeploymentServices{
						LabelSelector: &slim_metav1.LabelSelector{},
					},
					Nodes: isovalentv1alpha1.LBDeploymentNodes{
						LabelSelectors: &isovalentv1alpha1.LBDeploymentNodesLabelSelectors{
							T1: slim_metav1.LabelSelector{},
							T2: slim_metav1.LabelSelector{},
						},
					},
				},
				Status: isovalentv1alpha1.LBDeploymentStatus{Conditions: []metav1.Condition{{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"}}},
			},
			expectedNrOfConditions: 1,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "Valid",
			expectedMessage:        "Deployment is valid and accepted",
		},
		{
			desc: "Doesn't delete other conditions",
			lbd: &isovalentv1alpha1.LBDeployment{
				Spec: isovalentv1alpha1.LBDeploymentSpec{
					Services: isovalentv1alpha1.LBDeploymentServices{
						LabelSelector: &slim_metav1.LabelSelector{},
					},
					Nodes: isovalentv1alpha1.LBDeploymentNodes{
						LabelSelectors: &isovalentv1alpha1.LBDeploymentNodesLabelSelectors{
							T1: slim_metav1.LabelSelector{},
							T2: slim_metav1.LabelSelector{},
						},
					},
				},
				Status: isovalentv1alpha1.LBDeploymentStatus{Conditions: []metav1.Condition{
					{Type: "other-type", Status: metav1.ConditionTrue, Reason: "other-reason", Message: "other-message"},
					{Type: conditionType, Status: metav1.ConditionTrue, Reason: "reason", Message: "message"},
				}},
			},
			expectedNrOfConditions: 2,
			expectedStatus:         metav1.ConditionTrue,
			expectedReason:         "Valid",
			expectedMessage:        "Deployment is valid and accepted",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			r.updateAcceptedStatusCondition(tc.lbd)

			assert.Len(t, tc.lbd.Status.Conditions, tc.expectedNrOfConditions)

			c := tc.lbd.GetStatusCondition(conditionType)
			require.NotNil(t, c)
			assert.Equal(t, tc.expectedStatus, c.Status)
			assert.Equal(t, tc.expectedReason, c.Reason)
			assert.Equal(t, tc.expectedMessage, c.Message)
		})
	}
}
