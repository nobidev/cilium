//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package wafpolicy

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestResolveForLBService(t *testing.T) {
	defaults := GlobalDefaults{
		Enabled:       false,
		Mode:          isovalentv1alpha1.IsovalentWAFPolicyModeEnforce,
		PolicyProfile: isovalentv1alpha1.IsovalentWAFPolicyProfileBalanced,
		FailureMode:   isovalentv1alpha1.WAFFailureModeOpen,
	}

	service := &isovalentv1alpha1.LBService{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api",
			Namespace: "team-a",
			Labels: map[string]string{
				"app": "api",
			},
		},
	}

	inline := "SecRuleEngine DetectionOnly\n"
	mode := isovalentv1alpha1.IsovalentWAFPolicyModeMonitor
	overridePolicy := acceptedPolicy(
		"team-a",
		"api-waf",
		&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
	)
	overridePolicy.Spec.Enabled = true
	overridePolicy.Spec.Mode = &mode
	overridePolicy.Spec.Rules = &isovalentv1alpha1.IsovalentWAFPolicyRules{
		Custom: &isovalentv1alpha1.IsovalentWAFCustomRules{
			Inline: inline,
		},
	}

	conflictFirst := acceptedPolicy(
		"team-a",
		"first",
		&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
	)
	conflictSecond := acceptedPolicy(
		"team-a",
		"second",
		&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
	)

	pendingPolicy := acceptedPolicy(
		"team-a",
		"pending",
		&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
	)
	pendingPolicy.Generation = 2

	testCases := []struct {
		desc                    string
		policies                []isovalentv1alpha1.IsovalentWAFPolicy
		expectedState           ResolutionState
		expectedEffectiveConfig EffectiveConfig
		expectedPolicyRefsSize  int
	}{
		{
			desc:          "uses global defaults when no accepted match exists",
			expectedState: ResolutionStateResolved,
			expectedEffectiveConfig: EffectiveConfig{
				Enabled:         defaults.Enabled,
				Mode:            defaults.Mode,
				PolicyProfile:   defaults.PolicyProfile,
				FailureMode:     defaults.FailureMode,
				UsesGlobalRules: true,
			},
		},
		{
			desc:          "applies matching accepted policy overrides",
			policies:      []isovalentv1alpha1.IsovalentWAFPolicy{overridePolicy},
			expectedState: ResolutionStateResolved,
			expectedEffectiveConfig: EffectiveConfig{
				PolicyRef: &types.NamespacedName{
					Namespace: "team-a",
					Name:      "api-waf",
				},
				Enabled:         true,
				Mode:            mode,
				PolicyProfile:   defaults.PolicyProfile,
				FailureMode:     defaults.FailureMode,
				Inline:          &inline,
				UsesGlobalRules: false,
			},
			expectedPolicyRefsSize: 1,
		},
		{
			desc:          "rejects multiple accepted matches",
			policies:      []isovalentv1alpha1.IsovalentWAFPolicy{conflictFirst, conflictSecond},
			expectedState: ResolutionStateConflict,
			expectedEffectiveConfig: EffectiveConfig{
				Enabled:         defaults.Enabled,
				Mode:            defaults.Mode,
				PolicyProfile:   defaults.PolicyProfile,
				FailureMode:     defaults.FailureMode,
				UsesGlobalRules: true,
			},
			expectedPolicyRefsSize: 2,
		},
		{
			desc:          "waits for matching policy validation from current generation",
			policies:      []isovalentv1alpha1.IsovalentWAFPolicy{pendingPolicy},
			expectedState: ResolutionStatePending,
			expectedEffectiveConfig: EffectiveConfig{
				Enabled:         defaults.Enabled,
				Mode:            defaults.Mode,
				PolicyProfile:   defaults.PolicyProfile,
				FailureMode:     defaults.FailureMode,
				UsesGlobalRules: true,
			},
			expectedPolicyRefsSize: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			resolution, err := ResolveForLBService(service, tc.policies, defaults)
			require.NoError(t, err)

			require.Equal(t, tc.expectedState, resolution.State)
			require.Equal(t, tc.expectedEffectiveConfig, resolution.Config)
			require.Len(t, resolution.PolicyRefs, tc.expectedPolicyRefsSize)
		})
	}
}

func TestValidate(t *testing.T) {
	testCases := []struct {
		desc        string
		policy      isovalentv1alpha1.IsovalentWAFPolicy
		expectError bool
	}{
		{
			desc: "valid policy",
			policy: acceptedPolicy(
				"team-a",
				"valid",
				&slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			),
			expectError: false,
		},
		{
			desc: "invalid policy",
			policy: acceptedPolicy("team-a", "invalid", &slim_metav1.LabelSelector{
				MatchExpressions: []slim_metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: "BadOperator",
					},
				},
			}),
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			err := Validate(&tc.policy)
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func acceptedPolicy(
	namespace string,
	name string,
	selector *slim_metav1.LabelSelector,
) isovalentv1alpha1.IsovalentWAFPolicy {
	policy := isovalentv1alpha1.IsovalentWAFPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: isovalentv1alpha1.IsovalentWAFPolicySpec{
			Targets: isovalentv1alpha1.IsovalentWAFPolicyTargets{
				LBServices: &isovalentv1alpha1.IsovalentWAFPolicyLBServices{
					LabelSelector: selector,
				},
			},
			Enabled: true,
		},
	}

	policy.Status.Conditions = []metav1.Condition{{
		Type:               isovalentv1alpha1.ConditionTypeIsovalentWAFPolicyAccepted,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.IsovalentWAFPolicyAcceptedConditionReasonValid,
		Message:            "policy selector is valid",
		ObservedGeneration: policy.Generation,
		LastTransitionTime: metav1.Now(),
	}}
	policy.UpdateResourceStatus()

	return policy
}
