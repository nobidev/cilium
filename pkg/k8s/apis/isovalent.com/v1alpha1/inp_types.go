// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/comparator"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen:private-method=true
// +kubebuilder:resource:categories={cilium,ciliumpolicy,isovalent},singular="isovalentnetworkpolicy",path="isovalentnetworkpolicies",scope="Namespaced",shortName={inp,isovalentnp}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:printcolumn:JSONPath=".status.conditions[?(@.type=='Valid')].status",name="Valid",type=string
// +kubebuilder:subresource:status

// IsovalentNetworkPolicy is a Kubernetes third-party resource with an extended
// version of CiliumNetworkPolicy.
type IsovalentNetworkPolicy struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the desired Isovalent specific rule specification.
	//+kubebuilder:validation:XValidation:message="Order must be >= 0.0",rule="!has(self.order) || self.order >= 0.0"
	Spec *IsovalentNetworkPolicyRule `json:"spec,omitempty"`

	// Specs is a list of desired Isovalent specific rule specification.
	//+kubebuilder:validation:items:XValidation:message="Order must be >= 0.0",rule="!has(self.order) || self.order >= 0.0"
	Specs []*IsovalentNetworkPolicyRule `json:"specs,omitempty"`

	// Status is the status of the Isovalent policy rule
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status IsovalentNetworkPolicyStatus `json:"status"`
}

// DeepEqual compares 2 INPs.
func (in *IsovalentNetworkPolicy) DeepEqual(other *IsovalentNetworkPolicy) bool {
	return objectMetaDeepEqual(in.ObjectMeta, other.ObjectMeta) && in.deepEqual(other)
}

// objectMetaDeepEqual performs an equality check for metav1.ObjectMeta that
// ignores the LastAppliedConfigAnnotation. This function's usage is shared
// among INP and ICNP as they have the same structure.
func objectMetaDeepEqual(in, other metav1.ObjectMeta) bool {
	if !(in.Name == other.Name && in.Namespace == other.Namespace) {
		return false
	}

	return comparator.MapStringEqualsIgnoreKeys(
		in.GetAnnotations(),
		other.GetAnnotations(),
		// Ignore v1.LastAppliedConfigAnnotation annotation
		[]string{v1.LastAppliedConfigAnnotation})
}

// IsovalentNetworkPolicyRule is a policy rule which must be applied to all endpoints which match
// the labels contained in the endpointSelector
//
// Each rule is split into an ingress section which contains all rules
// applicable at ingress, and an egress section applicable at egress. For rule
// types such as `L4Rule` and `CIDR` which can be applied at both ingress and
// egress, both ingress and egress side have to either specifically allow the
// connection or one side has to be omitted.
//
// Either ingress, egress, or both can be provided. If both ingress and egress
// are omitted, the rule has no effect.
//
// +deepequal-gen:private-method=true
type IsovalentNetworkPolicyRule struct {
	api.Rule `json:",inline"`

	// Order specifies the order in which the policy is applied.
	Order *float32 `json:"order,omitempty"`
}

func (r *IsovalentNetworkPolicyRule) DeepEqual(o *IsovalentNetworkPolicyRule) bool {
	switch {
	case (r == nil) != (o == nil):
		return false
	case (r == nil) && (o == nil):
		return true
	}
	return r.deepEqual(o)
}

// +deepequal-gen=true

// IsovalentNetworkPolicyStatus is the status of an Isovalent policy rule.
type IsovalentNetworkPolicyStatus struct {
	// DerivativePolicies is the status of all policies derived from the Isovalent
	// policy
	DerivativePolicies map[string]IsovalentNetworkPolicyNodeStatus `json:"derivativePolicies,omitempty"`

	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []NetworkPolicyCondition `json:"conditions,omitempty"`
}

// +deepequal-gen=true

// IsovalentNetworkPolicyNodeStatus is the status of an Isovalent policy rule for a
// specific node.
type IsovalentNetworkPolicyNodeStatus struct {
	// OK is true when the policy has been parsed and imported successfully
	// into the in-memory policy repository on the node.
	OK bool `json:"ok,omitempty"`

	// Error describes any error that occurred when parsing or importing the
	// policy, or realizing the policy for the endpoints to which it applies
	// on the node.
	Error string `json:"error,omitempty"`

	// LastUpdated contains the last time this status was updated
	LastUpdated slimv1.Time `json:"lastUpdated,omitempty"`

	// Revision is the policy revision of the repository which first implemented
	// this policy.
	Revision uint64 `json:"localPolicyRevision,omitempty"`

	// Enforcing is set to true once all endpoints present at the time the
	// policy has been imported are enforcing this policy.
	Enforcing bool `json:"enforcing,omitempty"`

	// Annotations corresponds to the Annotations in the ObjectMeta of the INP
	// that have been realized on the node for INP. That is, if an INP has been
	// imported and has been assigned annotation X=Y by the user,
	// Annotations in IsovalentNetworkPolicyNodeStatus will be X=Y once the
	// INP that was imported corresponding to Annotation X=Y has been realized on
	// the node.
	Annotations map[string]string `json:"annotations,omitempty"`
}

func (r *IsovalentNetworkPolicy) String() string {
	result := ""
	result += fmt.Sprintf("TypeMeta: %s, ", r.TypeMeta.String())
	result += fmt.Sprintf("ObjectMeta: %s, ", r.ObjectMeta.String())
	if r.Spec != nil {
		result += fmt.Sprintf("Spec: %v", *(r.Spec))
	}
	if r.Specs != nil {
		result += fmt.Sprintf("Specs: %v", r.Specs)
	}
	result += fmt.Sprintf("Status: %v", r.Status)
	return result
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// IsovalentNetworkPolicyList is a list of IsovalentNetworkPolicy objects.
type IsovalentNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of IsovalentNetworkPolicy
	Items []IsovalentNetworkPolicy `json:"items"`
}

type PolicyConditionType string

const (
	PolicyConditionValid PolicyConditionType = "Valid"
)

type NetworkPolicyCondition struct {
	// The type of the policy condition
	Type PolicyConditionType `json:"type"`
	// The status of the condition, one of True, False, or Unknown
	Status v1.ConditionStatus `json:"status"`
	// The last time the condition transitioned from one status to another.
	// +optional
	LastTransitionTime slimv1.Time `json:"lastTransitionTime,omitempty"`
	// The reason for the condition's last transition.
	// +optional
	Reason string `json:"reason,omitempty"`
	// A human readable message indicating details about the transition.
	// +optional
	Message string `json:"message,omitempty"`
}
