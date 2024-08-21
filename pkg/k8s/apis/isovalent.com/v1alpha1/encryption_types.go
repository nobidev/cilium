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

// ClusterwideEncryptionPolicySpec defines a pod selector and a list of
// communication peer selectors for which traffic will be encrypted.
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
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Peers []ClusterwideEncryptionPeerSelector `json:"peers"`
}

// ClusterwideEncryptionPeerSelector defines a set of communication peers for
// which traffic will be encrypted
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
	// Ports is a list of ports on the peer for which traffic will be encrypted
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Ports []PortProtocol `json:"ports"`
}

// PortProtocol defines a L4 port and protocol
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
