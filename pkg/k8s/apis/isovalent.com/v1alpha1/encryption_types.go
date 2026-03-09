// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="isovalentclusterwideencryptionpolicy",path="isovalentclusterwideencryptionpolicies",scope="Cluster",shortName={icep}
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +deepequal-gen=false

// IsovalentClusterwideEncryptionPolicy defines the encryption policies for
// pods and their communication peers
type IsovalentClusterwideEncryptionPolicy struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec ClusterwideEncryptionPolicySpec `json:"spec"`
}

// ClusterwideEncryptionPolicySpec defines a pod selector and lists of
// communication peer selectors for which traffic will be encrypted or
// exempted from encryption. At least one of peers or plaintextPeers
// must be non-empty.
//
// +kubebuilder:validation:XValidation:rule="size(self.peers) > 0 || size(self.plaintextPeers) > 0",message="at least one of peers or plaintextPeers must be specified"
type ClusterwideEncryptionPolicySpec struct {
	// NamespaceSelector selects Namespaces using cluster-scoped labels.
	// This field follows standard label selector semantics. It is always
	// required. An empty but present (i.e. non-nil) selector acts as a
	// wildcard selector and selects all namespaces.
	//
	// +kubebuilder:validation:Required
	NamespaceSelector *slimv1.LabelSelector `json:"namespaceSelector"`
	// PodSelector is a label selector which selects Pods within the selected namespace.
	// This field follows standard label selector semantics. If absent or empty
	// it selects all pods within the namespace.
	//
	// +kubebuilder:validation:Optional
	PodSelector *slimv1.LabelSelector `json:"podSelector"`
	// Peers selects a list of communication peers for which traffic will be
	// encrypted.
	//
	// +kubebuilder:validation:Optional
	Peers []ClusterwideEncryptionPeerSelector `json:"peers,omitempty"`
	// PlaintextPeers selects a list of communication peers for which traffic
	// will be exempted from encryption. This is useful in combination with
	// fallbackBehavior: encrypt to opt-out specific flows from default encryption.
	//
	// +kubebuilder:validation:Optional
	PlaintextPeers []ClusterwideEncryptionPeerSelector `json:"plaintextPeers,omitempty"`
}

// ClusterwideEncryptionPeerSelector defines a set of communication peers.
// Whether traffic to these peers is encrypted or exempted from encryption
// depends on which field (peers or plaintextPeers) the selector appears in.
// Ports are optional: if omitted, all ports and protocols are matched.
// Specifying a protocol without a port (port defaults to 0) wildcards the
// port for that protocol (e.g. {protocol: "TCP"} means "all TCP ports").
type ClusterwideEncryptionPeerSelector struct {
	// NamespaceSelector selects Namespaces using cluster-scoped labels.
	// This field follows standard label selector semantics. It is always
	// required. An empty but present (i.e. non-nil) selector acts as a
	// wildcard selector and selects all namespaces.
	//
	// +kubebuilder:validation:Required
	NamespaceSelector *slimv1.LabelSelector `json:"namespaceSelector"`
	// PodSelector is a label selector which selects Pods within the selected namespace.
	// This field follows standard label selector semantics. If absent or empty
	// it selects all pods within the namespace.
	//
	// +kubebuilder:validation:Optional
	PodSelector *slimv1.LabelSelector `json:"podSelector"`
	// Ports is a list of L4 port/protocol pairs. If omitted or empty,
	// all ports and protocols are matched (wildcard).
	//
	// +kubebuilder:validation:Optional
	Ports []PortProtocol `json:"ports,omitempty"`
}

// PortProtocol defines a L4 port and protocol
//
// +kubebuilder:validation:XValidation:rule="self.port == 0 || (size(self.protocol) > 0  && self.protocol != 'ANY')",message="port requires a protocol to be specified"
type PortProtocol struct {
	// Port can be an L4 port number.
	//
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	Port uint16 `json:"port"`

	// Protocol is the L4 protocol. If omitted or empty, any protocol
	// matches. Accepted values: "TCP", "UDP", "SCTP", "ANY"
	//
	// +kubebuilder:validation:Enum=TCP;UDP;SCTP;ANY
	// +kubebuilder:validation:Optional
	Protocol string `json:"protocol,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// IsovalentClusterwideEncryptionPolicyList is a list of IsovalentClusterwideEncryptionPolicy objects.
type IsovalentClusterwideEncryptionPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of IsovalentEncryptionPolicys.
	Items []IsovalentClusterwideEncryptionPolicy `json:"items"`
}
