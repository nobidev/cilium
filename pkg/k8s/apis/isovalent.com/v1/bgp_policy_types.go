// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalentbgp},singular="isovalentbgppolicy",path="isovalentbgppolicies",scope="Cluster",shortName={ibgppolicy}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

// IsovalentBGPPolicy is the Schema for the isovalentbgppolicies API
type IsovalentBGPPolicy struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	Spec IsovalentBGPPolicySpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// IsovalentBGPPolicyList contains a list of IsovalentBGPPolicy
type IsovalentBGPPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of IsovalentBGPPolicy.
	Items []IsovalentBGPPolicy `json:"items"`
}

type IsovalentBGPPolicySpec struct {
	// Import defines the BGP import policy.
	//
	// +kubebuilder:validation:Required
	Import BGPImportPolicy `json:"import"`
}

// BGPImportPolicy defines the BGP import policy.
type BGPImportPolicy struct {
	// Statements is a list of BGP policy statements.
	//
	// +kubebuilder:validation:MinItems=1
	Statements []BGPPolicyStatement `json:"statements"`
}

// BGPPolicyStatement defines a single BGP policy statement.
type BGPPolicyStatement struct {
	// Conditions defines the conditions to match routes for this statement.
	//
	// +kubebuilder:validation:Required
	Conditions BGPPolicyConditions `json:"conditions"`

	// Actions defines the actions to take when the conditions are met.
	//
	// +kubebuilder:validation:Required
	Actions BGPPolicyActions `json:"actions"`
}

// +kubebuilder:validation:Enum=Or
type BGPPolicyMatchType string

const (
	// BGPPolicyMatchTypeOr represents a logical OR match type.
	BGPPolicyMatchTypeOr BGPPolicyMatchType = "Or"
)

// BGPPolicyConditions defines the conditions to match routes for a BGP policy statement.
//
// +kubebuilder:validation:XValidation:rule="has(self.prefixesV4) || has(self.prefixesV6)", message="At least one of prefixesV4 or prefixesV6 must be specified"
type BGPPolicyConditions struct {
	// PrefixesV4 defines conditions to match IPv4 prefixes.
	//
	// +kubebuilder:validation:Optional
	PrefixesV4 *PrefixesV4Condition `json:"prefixesV4,omitempty"`

	// PrefixesV6 defines conditions to match IPv6 prefixes.
	//
	// +kubebuilder:validation:Optional
	PrefixesV6 *PrefixesV6Condition `json:"prefixesV6,omitempty"`
}

// PrefixesV4Condition defines a condition to match IPv4 prefixes.
type PrefixesV4Condition struct {
	// Type of match to perform.
	//
	// +kubebuilder:validation:Required
	MatchType BGPPolicyMatchType `json:"matchType"`

	// List of IPv4 prefix matches.
	//
	// +kubebuilder:validation:MinItems=1
	Matches []PrefixV4Match `json:"matches"`
}

// PrefixV4Match defines a single IPv4 prefix match.
type PrefixV4Match struct {
	// Prefix is the IPv4 prefix to match.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=cidr
	Prefix string `json:"prefix"`

	// Maximum prefix length for the match. If not specified, it defaults
	// to the prefix length.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=32
	MaxLen *uint8 `json:"maxLen,omitempty"`

	// Minimum prefix length for the match. It must be less than or equal
	// to maxLen. If not specified, it defaults to the maxLen.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=32
	MinLen *uint8 `json:"minLen,omitempty"`
}

// PrefixesV6Condition defines a condition to match IPv6 prefixes.
type PrefixesV6Condition struct {
	// Type of match to perform.
	//
	// +kubebuilder:validation:Required
	MatchType BGPPolicyMatchType `json:"matchType"`

	// List of IPv6 prefix matches.
	//
	// +kubebuilder:validation:MinItems=1
	Matches []PrefixV6Match `json:"matches"`
}

// PrefixV6Match defines a single IPv6 prefix match.
type PrefixV6Match struct {
	// Prefix is the IPv6 prefix to match.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=cidr
	Prefix string `json:"prefix"`

	// Maximum prefix length for the match. If not specified, it defaults
	// to the prefix length.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=128
	MaxLen *uint8 `json:"maxLen,omitempty"`

	// Minimum prefix length for the match. It must be less than or equal
	// to maxLen. If not specified, it defaults to the maxLen.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=128
	MinLen *uint8 `json:"minLen,omitempty"`
}

// BGPPolicyActions defines the actions to take when the conditions are met.
type BGPPolicyActions struct {
	// RouteAction defines the action to take on the matched routes.
	//
	// +kubebuilder:validation:Required
	RouteAction BGPRouteAction `json:"routeAction"`
}

// +kubebuilder:validation:Enum=Accept
type BGPRouteAction string

const (
	// BGPRouteActionAccept represents an action to accept the matched routes.
	BGPRouteActionAccept BGPRouteAction = "Accept"
)
