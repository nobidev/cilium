// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/comparator"
	k8sCiliumUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen:private-method=true
// +kubebuilder:resource:categories={cilium,ciliumpolicy,isovalent},singular="isovalentnetworkpolicy",path="isovalentnetworkpolicies",scope="Namespaced",shortName={inp,isovalentnp}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:printcolumn:JSONPath=".status.conditions[?(@.type=='Valid')].status",name="Valid",type=string
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

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

// MarshalJSON returns the JSON encoding of r. It is like api.Rule.MarshalJSON (which would be used
// without this method being defined because api.Rule is embedded) but also marshals the Order field.
func (r *IsovalentNetworkPolicyRule) MarshalJSON() ([]byte, error) {
	type common struct {
		Ingress           []api.IngressRule      `json:"ingress,omitempty"`
		IngressDeny       []api.IngressDenyRule  `json:"ingressDeny,omitempty"`
		Egress            []api.EgressRule       `json:"egress,omitempty"`
		EgressDeny        []api.EgressDenyRule   `json:"egressDeny,omitempty"`
		Labels            labels.LabelArray      `json:"labels,omitempty"`
		EnableDefaultDeny *api.DefaultDenyConfig `json:"enableDefaultDeny,omitempty"`
		Description       string                 `json:"description,omitempty"`
		Order             *float32               `json:"order,omitempty"`
	}

	var a interface{}
	ruleCommon := common{
		Ingress:     r.Ingress,
		IngressDeny: r.IngressDeny,
		Egress:      r.Egress,
		EgressDeny:  r.EgressDeny,
		Labels:      r.Labels,
		Description: r.Description,
		Order:       r.Order,
	}

	// TODO: convert this to `omitzero` when Go v1.24 is released
	if r.EnableDefaultDeny.Egress != nil || r.EnableDefaultDeny.Ingress != nil {
		ruleCommon.EnableDefaultDeny = &r.EnableDefaultDeny
	}

	// Only one of endpointSelector or nodeSelector is permitted.
	switch {
	case r.EndpointSelector.LabelSelector != nil:
		a = struct {
			EndpointSelector api.EndpointSelector `json:"endpointSelector,omitempty"`
			common
		}{
			EndpointSelector: r.EndpointSelector,
			common:           ruleCommon,
		}
	case r.NodeSelector.LabelSelector != nil:
		a = struct {
			NodeSelector api.EndpointSelector `json:"nodeSelector,omitempty"`
			common
		}{
			NodeSelector: r.NodeSelector,
			common:       ruleCommon,
		}
	}

	return json.Marshal(a)
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

// CreateINPNodeStatus returns an IsovalentNetworkPolicyNodeStatus created from the
// provided fields.
func CreateINPNodeStatus(enforcing, ok bool, inpError error, rev uint64, annotations map[string]string) IsovalentNetworkPolicyNodeStatus {
	inpns := IsovalentNetworkPolicyNodeStatus{
		Enforcing:   enforcing,
		Revision:    rev,
		OK:          ok,
		LastUpdated: slimv1.Now(),
		Annotations: annotations,
	}
	if inpError != nil {
		inpns.Error = inpError.Error()
	}
	return inpns
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

// SetDerivedPolicyStatus set the derivative policy status for the given
// derivative policy name.
func (r *IsovalentNetworkPolicy) SetDerivedPolicyStatus(derivativePolicyName string, status IsovalentNetworkPolicyNodeStatus) {
	if r.Status.DerivativePolicies == nil {
		r.Status.DerivativePolicies = map[string]IsovalentNetworkPolicyNodeStatus{}
	}
	r.Status.DerivativePolicies[derivativePolicyName] = status
}

// Parse parses an IsovalentNetworkPolicy and returns a list of cilium policy
// rules.
func (r *IsovalentNetworkPolicy) Parse(logger *slog.Logger, clusterName string) (api.Rules, error) {
	if r.ObjectMeta.Name == "" {
		return nil, NewErrParse("IsovalentNetworkPolicy must have name")
	}

	namespace := k8sUtils.ExtractNamespace(&r.ObjectMeta)
	// Temporary fix for ICNPs. See #12834 (which refers to CCNPs).
	// TL;DR. ICNPs are converted into SlimINPs and end up here so we need to
	// convert them back to ICNPs to allow proper parsing.
	if namespace == "" {
		icnp := IsovalentClusterwideNetworkPolicy{
			TypeMeta:   r.TypeMeta,
			ObjectMeta: r.ObjectMeta,
			Spec:       r.Spec,
			Specs:      r.Specs,
			Status:     r.Status,
		}
		return icnp.Parse(logger, clusterName)
	}
	name := r.ObjectMeta.Name
	uid := r.ObjectMeta.UID

	retRules := api.Rules{}

	if r.Spec == nil && r.Specs == nil {
		return nil, ErrEmptyINP
	}

	if r.Spec != nil {
		if err := r.Spec.Sanitize(); err != nil {
			return nil, NewErrParse(fmt.Sprintf("Invalid IsovalentNetworkPolicy spec: %s", err))
		}
		if r.Spec.NodeSelector.LabelSelector != nil {
			return nil, NewErrParse("Invalid IsovalentNetworkPolicy spec: rule cannot have NodeSelector")
		}
		if err := r.Spec.SanitizeOrder(); err != nil {
			return nil, NewErrParse(fmt.Sprintf("Invalid IsovalentNetworkPolicy spec: %s", err))
		}
		cr := r.Spec.parseToIsovalentNetworkPolicyRule(logger, clusterName, namespace, name, uid)
		retRules = append(retRules, cr)
	}
	if r.Specs != nil {
		for _, rule := range r.Specs {
			if err := rule.Sanitize(); err != nil {
				return nil, NewErrParse(fmt.Sprintf("Invalid IsovalentNetworkPolicy specs: %s", err))

			}
			if err := rule.SanitizeOrder(); err != nil {
				return nil, NewErrParse(fmt.Sprintf("Invalid IsovalentNetworkPolicy specs: %s", err))
			}
			cr := rule.parseToIsovalentNetworkPolicyRule(logger, clusterName, namespace, name, uid)
			retRules = append(retRules, cr)
		}
	}

	return retRules, nil
}

func (r *IsovalentNetworkPolicyRule) SanitizeOrder() error {
	if order := r.Order; order != nil && *order < 0 {
		return errors.New("rule order must be ≥ 0")
	}
	return nil
}

func (r *IsovalentNetworkPolicyRule) parseToIsovalentNetworkPolicyRule(logger *slog.Logger, clusterName, namespace, name string, uid types.UID) *api.Rule {
	cr := k8sCiliumUtils.ParseToCiliumRule(logger, clusterName, namespace, name, uid, &r.Rule)
	// TODO: uncomment in ft/main-ce/ordered-policy, check for order ≥ 0 for INP (but not ICNP)
	// cr.OrderCEEOnly = r.Spec.Order
	return cr
}

// GetIdentityLabels returns all rule labels in the IsovalentNetworkPolicy.
func (r *IsovalentNetworkPolicy) GetIdentityLabels() labels.LabelArray {
	namespace := k8sUtils.ExtractNamespace(&r.ObjectMeta)
	name := r.ObjectMeta.Name
	uid := r.ObjectMeta.UID

	// Even though the struct represents IsovalentNetworkPolicy, we use it both for
	// IsovalentNetworkPolicy and IsovalentClusterwideNetworkPolicy, so here we check for namespace
	// to send correct derivedFrom label to get the correct policy labels.
	derivedFrom := IsovalentNetworkPolicyKindDefinition
	if namespace == "" {
		derivedFrom = IsovalentClusterwideNetworkPolicyKindDefinition
	}
	return k8sCiliumUtils.GetPolicyLabels(namespace, name, uid, derivedFrom)
}

// RequiresDerivative return true if the CNP has any rule that will create a new
// derivative rule.
func (r *IsovalentNetworkPolicy) RequiresDerivative() bool {
	if r.Spec != nil {
		if r.Spec.RequiresDerivative() {
			return true
		}
	}
	if r.Specs != nil {
		for _, rule := range r.Specs {
			if rule.RequiresDerivative() {
				return true
			}
		}
	}
	return false
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
