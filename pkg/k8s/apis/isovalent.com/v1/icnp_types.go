// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1

import (
	"errors"
	"iter"
	"log/slog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policytypes "github.com/cilium/cilium/pkg/policy/types"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen:private-method=true
// +kubebuilder:resource:categories={cilium,ciliumpolicy,isovalent},singular="isovalentclusterwidenetworkpolicy",path="isovalentclusterwidenetworkpolicies",scope="Cluster",shortName={icnp}
// +kubebuilder:printcolumn:JSONPath=".status.conditions[?(@.type=='Valid')].status",name="Valid",type=string
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// IsovalentClusterwideNetworkPolicy is a Kubernetes third-party resource with an
// modified version of IsovalentNetworkPolicy which is cluster scoped rather than
// namespace scoped.
type IsovalentClusterwideNetworkPolicy struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the desired Isovalent specific rule specification.
	Spec *IsovalentNetworkPolicyRule `json:"spec,omitempty"`

	// Specs is a list of desired Isovalent specific rule specification.
	Specs []*IsovalentNetworkPolicyRule `json:"specs,omitempty"`

	// Status is the status of the Isovalent policy rule.
	//
	// The reason this field exists in this structure is due a bug in the k8s
	// code-generator that doesn't create a `UpdateStatus` method because the
	// field does not exist in the structure.
	//
	// +kubebuilder:validation:Optional
	Status IsovalentNetworkPolicyStatus `json:"status"`
}

// DeepEqual compares 2 CCNPs while ignoring the LastAppliedConfigAnnotation
// and ignoring the Status field of the CCNP.
func (in *IsovalentClusterwideNetworkPolicy) DeepEqual(other *IsovalentClusterwideNetworkPolicy) bool {
	return objectMetaDeepEqual(in.ObjectMeta, other.ObjectMeta) && in.deepEqual(other)
}

// SetDerivedPolicyStatus set the derivative policy status for the given
// derivative policy name.
func (r *IsovalentClusterwideNetworkPolicy) SetDerivedPolicyStatus(derivativePolicyName string, status IsovalentNetworkPolicyNodeStatus) {
	if r.Status.DerivativePolicies == nil {
		r.Status.DerivativePolicies = map[string]IsovalentNetworkPolicyNodeStatus{}
	}
	r.Status.DerivativePolicies[derivativePolicyName] = status
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// IsovalentClusterwideNetworkPolicyList is a list of
// IsovalentClusterwideNetworkPolicy objects.
type IsovalentClusterwideNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of IsovalentClusterwideNetworkPolicies.
	Items []IsovalentClusterwideNetworkPolicy `json:"items"`
}

func (r *IsovalentClusterwideNetworkPolicy) rules() iter.Seq[*IsovalentNetworkPolicyRule] {
	return func(yield func(*IsovalentNetworkPolicyRule) bool) {
		if r.Spec != nil {
			if !yield(r.Spec) {
				return
			}
		}

		for _, rule := range r.Specs {
			if rule != nil {
				if !yield(rule) {
					return
				}
			}
		}
	}
}

func (r *IsovalentClusterwideNetworkPolicy) Sanitize() error {
	var errs error
	if r.ObjectMeta.Name == "" {
		errs = errors.Join(errs, NewErrParse("IsovalentClusterwideNetworkPolicy must have name"))
	}
	if r.ObjectMeta.Namespace != "" {
		errs = errors.Join(errs, NewErrParse("IsovalentClusterwideNetworkPolicy must not have namespace"))
	}
	if r.Spec == nil && r.Specs == nil {
		errs = errors.Join(errs, ErrEmptyICNP)
	}
	for rule := range r.rules() {
		errs = errors.Join(errs, rule.Sanitize(true))
	}
	return errs
}

// Parse parses an IsovalentClusterwideNetworkPolicy and returns a list of cilium
// policy rules.
func (r *IsovalentClusterwideNetworkPolicy) Parse(logger *slog.Logger, clusterName string) (policytypes.PolicyEntries, error) {
	if err := r.Sanitize(); err != nil {
		return nil, err
	}
	out := make(policytypes.PolicyEntries, 0, len(r.Specs)+1)

	for rule := range r.rules() {
		entries := rule.parseToPolicyEntries(logger, clusterName, r.ObjectMeta)
		out = append(out, entries...)
	}

	return out, nil
}
