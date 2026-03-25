// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent,loadbalancer},singular="isovalentwafpolicy",path="isovalentwafpolicies",scope="Namespaced",shortName={wafpolicy}
// +kubebuilder:printcolumn:JSONPath=".status.status",name="Status",type=string
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// IsovalentWAFPolicy defines reusable WAF settings and custom rules that can be
// attached to selected resources within the same namespace. For MVP, targets
// only support LBServices.
type IsovalentWAFPolicy struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec IsovalentWAFPolicySpec `json:"spec"`

	// +kubebuilder:validation:Optional
	Status IsovalentWAFPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:validation:XValidation:message="spec.targets.lbServices must be specified",rule="has(self.targets.lbServices)"
type IsovalentWAFPolicySpec struct {
	// Targets defines the resources that this WAF policy should apply to.
	//
	// +kubebuilder:validation:Required
	Targets IsovalentWAFPolicyTargets `json:"targets"`

	// Enabled explicitly enables or disables WAF for the selected resources.
	//
	// +kubebuilder:validation:Required
	Enabled bool `json:"enabled"`

	// Mode controls whether WAF only monitors traffic or actively enforces decisions.
	// If omitted, the global WAF setting is used.
	//
	// +kubebuilder:validation:Optional
	Mode *IsovalentWAFPolicyModeType `json:"mode,omitempty"`

	// FailureMode controls what happens when the WAF backend cannot evaluate a request.
	// If omitted, the global WAF setting is used.
	//
	// +kubebuilder:validation:Optional
	FailureMode *WAFFailureModeType `json:"failureMode,omitempty"`

	// Rules selects either a managed WAF profile or a fully custom ruleset.
	// If omitted, the global WAF rules are used.
	//
	// +kubebuilder:validation:Optional
	Rules *IsovalentWAFPolicyRules `json:"rules,omitempty"`
}

type IsovalentWAFPolicyTargets struct {
	// LBServices selects the LBServices that should be handled by this
	// IsovalentWAFPolicy.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	LBServices *IsovalentWAFPolicyLBServices `json:"lbServices,omitempty"`
}

type IsovalentWAFPolicyLBServices struct {
	// LabelSelector is a label selector that selects the LBServices within the same namespace.
	//
	// Note: An empty label selector (neither MatchLabels nor MatchExpressions defined)
	// matches all LBServices in the same namespace.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:AnyOf
	LabelSelector *slim_metav1.LabelSelector `json:"labelSelector,omitempty"`
}

// +kubebuilder:validation:XValidation:message="exactly one of managed or custom must be specified",rule="has(self.managed) != has(self.custom)"
type IsovalentWAFPolicyRules struct {
	// Managed selects the built-in WAF rules shipped by the platform.
	//
	// +kubebuilder:validation:Optional
	Managed *IsovalentWAFManagedRules `json:"managed,omitempty"`

	// Custom provides a fully custom WAF ruleset.
	//
	// +kubebuilder:validation:Optional
	Custom *IsovalentWAFCustomRules `json:"custom,omitempty"`
}

type IsovalentWAFManagedRules struct {
	// Profile selects the built-in WAF profile to use with managed rules.
	//
	// +kubebuilder:validation:Required
	Profile IsovalentWAFPolicyProfileType `json:"profile"`
}

type IsovalentWAFCustomRules struct {
	// Inline provides a fully custom WAF ruleset directly in the resource.
	// Multi-line values should be provided as a YAML block scalar.
	//
	// +kubebuilder:validation:Required
	Inline string `json:"inline"`
}

// +kubebuilder:validation:Enum=Monitor;Enforce
type IsovalentWAFPolicyModeType string

const (
	IsovalentWAFPolicyModeMonitor IsovalentWAFPolicyModeType = "Monitor"
	IsovalentWAFPolicyModeEnforce IsovalentWAFPolicyModeType = "Enforce"
)

// +kubebuilder:validation:Enum=max_security;high_security;balanced;low_friction;min_friction
type IsovalentWAFPolicyProfileType string

const (
	IsovalentWAFPolicyProfileMaxSecurity  IsovalentWAFPolicyProfileType = "max_security"
	IsovalentWAFPolicyProfileHighSecurity IsovalentWAFPolicyProfileType = "high_security"
	IsovalentWAFPolicyProfileBalanced     IsovalentWAFPolicyProfileType = "balanced"
	IsovalentWAFPolicyProfileLowFriction  IsovalentWAFPolicyProfileType = "low_friction"
	IsovalentWAFPolicyProfileMinFriction  IsovalentWAFPolicyProfileType = "min_friction"
)

// +kubebuilder:validation:Enum=Open;Close
type WAFFailureModeType string

const (
	WAFFailureModeOpen  WAFFailureModeType = "Open"
	WAFFailureModeClose WAFFailureModeType = "Close"
)

type IsovalentWAFPolicyStatus struct {
	// The current conditions of the IsovalentWAFPolicy.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Status of the resource.
	//
	// +kubebuilder:validation:Required
	Status LBResourceStatus `json:"status"`
}

const (
	ConditionTypeIsovalentWAFPolicyAccepted = "Accepted"
)

const (
	IsovalentWAFPolicyAcceptedConditionReasonValid   = "Valid"
	IsovalentWAFPolicyAcceptedConditionReasonInvalid = "Invalid"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +deepequal-gen=false
type IsovalentWAFPolicyList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []IsovalentWAFPolicy `json:"items"`
}

func (r *IsovalentWAFPolicy) GetStatusCondition(conditionType string) *metav1.Condition {
	for _, c := range r.Status.Conditions {
		if c.Type == conditionType {
			return &c
		}
	}
	return nil
}

func (r *IsovalentWAFPolicy) UpsertStatusCondition(conditionType string, condition metav1.Condition) {
	conditionExists := false
	for i, c := range r.Status.Conditions {
		if c.Type == conditionType {
			if c.Status != condition.Status ||
				c.Reason != condition.Reason ||
				c.Message != condition.Message ||
				c.ObservedGeneration != condition.ObservedGeneration {
				r.Status.Conditions[i] = condition
			}
			conditionExists = true
			break
		}
	}

	if !conditionExists {
		r.Status.Conditions = append(r.Status.Conditions, condition)
	}
}

func (r *IsovalentWAFPolicy) UpdateResourceStatus() {
	resourceStatus := LBResourceStatusOK

	for _, c := range r.Status.Conditions {
		if c.Status == metav1.ConditionFalse {
			resourceStatus = LBResourceStatusConditionNotMet
			break
		}
	}

	r.Status.Status = resourceStatus
}

func (in *IsovalentWAFPolicy) DeepCopyInto(out *IsovalentWAFPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *IsovalentWAFPolicy) DeepCopy() *IsovalentWAFPolicy {
	if in == nil {
		return nil
	}
	out := new(IsovalentWAFPolicy)
	in.DeepCopyInto(out)
	return out
}

func (in *IsovalentWAFPolicyList) DeepCopyInto(out *IsovalentWAFPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IsovalentWAFPolicy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

func (in *IsovalentWAFPolicyList) DeepCopy() *IsovalentWAFPolicyList {
	if in == nil {
		return nil
	}
	out := new(IsovalentWAFPolicyList)
	in.DeepCopyInto(out)
	return out
}

func (in *IsovalentWAFPolicySpec) DeepCopyInto(out *IsovalentWAFPolicySpec) {
	*out = *in
	in.Targets.DeepCopyInto(&out.Targets)
	if in.Mode != nil {
		in, out := &in.Mode, &out.Mode
		*out = new(IsovalentWAFPolicyModeType)
		**out = **in
	}
	if in.FailureMode != nil {
		in, out := &in.FailureMode, &out.FailureMode
		*out = new(WAFFailureModeType)
		**out = **in
	}
	if in.Rules != nil {
		in, out := &in.Rules, &out.Rules
		*out = new(IsovalentWAFPolicyRules)
		(*in).DeepCopyInto(*out)
	}
}

func (in *IsovalentWAFPolicySpec) DeepCopy() *IsovalentWAFPolicySpec {
	if in == nil {
		return nil
	}
	out := new(IsovalentWAFPolicySpec)
	in.DeepCopyInto(out)
	return out
}

func (in *IsovalentWAFPolicyTargets) DeepCopyInto(out *IsovalentWAFPolicyTargets) {
	*out = *in
	if in.LBServices != nil {
		in, out := &in.LBServices, &out.LBServices
		*out = new(IsovalentWAFPolicyLBServices)
		(*in).DeepCopyInto(*out)
	}
}

func (in *IsovalentWAFPolicyTargets) DeepCopy() *IsovalentWAFPolicyTargets {
	if in == nil {
		return nil
	}
	out := new(IsovalentWAFPolicyTargets)
	in.DeepCopyInto(out)
	return out
}

func (in *IsovalentWAFPolicyLBServices) DeepCopyInto(out *IsovalentWAFPolicyLBServices) {
	*out = *in
	if in.LabelSelector != nil {
		in, out := &in.LabelSelector, &out.LabelSelector
		*out = new(slim_metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
}

func (in *IsovalentWAFPolicyLBServices) DeepCopy() *IsovalentWAFPolicyLBServices {
	if in == nil {
		return nil
	}
	out := new(IsovalentWAFPolicyLBServices)
	in.DeepCopyInto(out)
	return out
}

func (in *IsovalentWAFPolicyRules) DeepCopyInto(out *IsovalentWAFPolicyRules) {
	*out = *in
	if in.Managed != nil {
		in, out := &in.Managed, &out.Managed
		*out = new(IsovalentWAFManagedRules)
		**out = **in
	}
	if in.Custom != nil {
		in, out := &in.Custom, &out.Custom
		*out = new(IsovalentWAFCustomRules)
		**out = **in
	}
}

func (in *IsovalentWAFPolicyRules) DeepCopy() *IsovalentWAFPolicyRules {
	if in == nil {
		return nil
	}
	out := new(IsovalentWAFPolicyRules)
	in.DeepCopyInto(out)
	return out
}

func (in *IsovalentWAFManagedRules) DeepCopyInto(out *IsovalentWAFManagedRules) {
	*out = *in
}

func (in *IsovalentWAFManagedRules) DeepCopy() *IsovalentWAFManagedRules {
	if in == nil {
		return nil
	}
	out := new(IsovalentWAFManagedRules)
	in.DeepCopyInto(out)
	return out
}

func (in *IsovalentWAFCustomRules) DeepCopyInto(out *IsovalentWAFCustomRules) {
	*out = *in
}

func (in *IsovalentWAFCustomRules) DeepCopy() *IsovalentWAFCustomRules {
	if in == nil {
		return nil
	}
	out := new(IsovalentWAFCustomRules)
	in.DeepCopyInto(out)
	return out
}

func (in *IsovalentWAFPolicyStatus) DeepCopyInto(out *IsovalentWAFPolicyStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]metav1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

func (in *IsovalentWAFPolicyStatus) DeepCopy() *IsovalentWAFPolicyStatus {
	if in == nil {
		return nil
	}
	out := new(IsovalentWAFPolicyStatus)
	in.DeepCopyInto(out)
	return out
}
