// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// IsovalentBGPPeerConfigList is a list of CiliumBGPPeer objects.
type IsovalentBGPPeerConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumBGPPeer.
	Items []IsovalentBGPPeerConfig `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalentbgp},singular="isovalentbgppeerconfig",path="isovalentbgppeerconfigs",scope="Cluster",shortName={ibgppeer}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:deprecatedversion

type IsovalentBGPPeerConfig struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the specification of the desired behavior of the IsovalentBGPPeerConfig.
	Spec IsovalentBGPPeerConfigSpec `json:"spec"`

	// Status is the running status of the IsovalentBGPPeerConfig
	//
	// +kubebuilder:validation:Optional
	Status IsovalentBGPPeerConfigStatus `json:"status"`
}

type IsovalentBGPPeerConfigSpec struct {
	v2alpha1.CiliumBGPPeerConfigSpec `json:",inline"`

	// BFDProfileRef is the name of the BFD profile used to establish a BFD (Bidirectional Forwarding Detection)
	// session with the peer. If not set, BFD is not used for this peer.
	//
	// +kubebuilder:validation:Optional
	BFDProfileRef *string `json:"bfdProfileRef,omitempty"`
}

type IsovalentBGPPeerConfigStatus struct {
	// The current conditions of the CiliumBGPPeerConfig
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Conditions for IsovalentBGPPeerConfig
const (
	// Referenced auth secret is missing
	BGPPeerConfigConditionMissingAuthSecret = "isovalent.com/MissingAuthSecret"
	// Referenced BFDProfile is missing
	BGPPeerConfigConditionMissingBFDProfile = "isovalent.com/MissingBFDProfile"
)

var AllBGPPeerConfigConditions = []string{
	BGPPeerConfigConditionMissingAuthSecret,
	BGPPeerConfigConditionMissingBFDProfile,
}
