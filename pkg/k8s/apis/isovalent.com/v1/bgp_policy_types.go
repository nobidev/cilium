// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
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

// +kubebuilder:validation:Enum=Or;And;Not
type BGPPolicyMatchType string

const (
	// BGPPolicyMatchTypeOr represents a logical OR match type.
	BGPPolicyMatchTypeOr BGPPolicyMatchType = "Or"

	// BGPPolicyMatchTypeAnd represents a logical AND match type.
	BGPPolicyMatchTypeAnd BGPPolicyMatchType = "And"

	// BGPPolicyMatchTypeNot represents a logical NOT match type.
	BGPPolicyMatchTypeNot BGPPolicyMatchType = "Not"
)

// BGPPolicyConditions defines the conditions to match routes for a BGP policy statement.
//
// +kubebuilder:validation:XValidation:rule="has(self.prefixesV4) || has(self.prefixesV6) || has(self.communities) || has(self.largeCommunities)", message="At least one condition must be specified"
type BGPPolicyConditions struct {
	// PrefixesV4 defines conditions to match IPv4 prefixes.
	//
	// +kubebuilder:validation:Optional
	PrefixesV4 *PrefixesV4Condition `json:"prefixesV4,omitempty"`

	// PrefixesV6 defines conditions to match IPv6 prefixes.
	//
	// +kubebuilder:validation:Optional
	PrefixesV6 *PrefixesV6Condition `json:"prefixesV6,omitempty"`

	// Communities defines conditions to match BGP communities.
	//
	// +kubebuilder:validation:Optional
	Communities *CommunitiesCondition `json:"communities,omitempty"`

	// LargeCommunities defines conditions to match BGP large communities.
	//
	// +kubebuilder:validation:Optional
	LargeCommunities *LargeCommunitiesCondition `json:"largeCommunities,omitempty"`
}

// PrefixesV4Condition defines a condition to match IPv4 prefixes.
//
// +kubebuilder:validation:XValidation:rule="self.matchType != 'And'", message="'And' matchType is not supported for prefix matching"
type PrefixesV4Condition struct {
	// Type of match to perform.
	// 'And' matchType is not supported.
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
//
// +kubebuilder:validation:XValidation:rule="self.matchType != 'And'", message="'And' matchType is not supported for prefix matching"
type PrefixesV6Condition struct {
	// Type of match to perform.
	// 'And' matchType is not supported.
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

// CommunitiesCondition defines a condition to match BGP communities.
type CommunitiesCondition struct {
	// Type of match to perform.
	//
	// +kubebuilder:validation:Required
	MatchType BGPPolicyMatchType `json:"matchType"`

	// List of BGP communities to match with.
	//
	// +kubebuilder:validation:MinItems=1
	Matches []CommunityMatch `json:"matches"`
}

// CommunityMatch defines a single BGP community match.
//
// +kubebuilder:validation:XValidation:rule="has(self.community) != has(self.wellKnown)", message="Either community or wellKnown must be specified"
type CommunityMatch struct {
	// Community holds a "standard" 32-bit BGP community value defined as
	// a 4-byte decimal number or two 2-byte decimal numbers separated by a colon (<0-65535>:<0-65535>).
	//
	// +kubebuilder:validation:Optional
	Community *v2.BGPStandardCommunity `json:"community,omitempty"`

	// WellKnown holds a "standard" 32-bit BGP community value defined as well-known string alias to its numeric value.
	//
	// +kubebuilder:validation:Optional
	WellKnown *v2.BGPWellKnownCommunity `json:"wellKnown,omitempty"`
}

// LargeCommunitiesCondition defines a condition to match BGP large communities.
type LargeCommunitiesCondition struct {
	// Type of match to perform.
	//
	// +kubebuilder:validation:Required
	MatchType BGPPolicyMatchType `json:"matchType"`

	// List of BGP large communities to match with.
	//
	// +kubebuilder:validation:MinItems=1
	Matches []LargeCommunityMatch `json:"matches"`
}

// LargeCommunityMatch defines a single BGP large community match.
type LargeCommunityMatch struct {
	// Community holds a BGP large community value as three 4-byte decimal numbers separated by colons.
	//
	// +kubebuilder:validation:Required
	Community v2.BGPLargeCommunity `json:"community,omitempty"`
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
