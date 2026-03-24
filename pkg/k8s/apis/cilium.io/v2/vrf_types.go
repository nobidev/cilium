// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumvrf",path="ciliumvrfs",scope="Cluster",shortName={cvrf}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

// CiliumVRF defines a Virtual Routing and Forwarding domain that binds
// selected pods and network interfaces into an isolated routing table.
type CiliumVRF struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Required
	metav1.ObjectMeta `json:"metadata"`

	// Spec defines the desired VRF configuration.
	//
	// +kubebuilder:validation:Required
	Spec CiliumVRFSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumVRFList is a list of CiliumVRF objects.
type CiliumVRFList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumVRF.
	Items []CiliumVRF `json:"items"`
}

// CiliumVRFSpec defines the desired state of a CiliumVRF.
type CiliumVRFSpec struct {
	// ID is used to group a set of CiliumVRFs into a single VRF instance.
	// This provides decoupling and allows a VRF to utilize different table IDs
	// and interfaces across nodes.
	//
	// The ID zero is used internally and is reserved.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	ID uint64 `json:"id"`

	// Table is the routing table ID for this VRF.
	// Must be provided by the creator (user, BGP controller, or network manager).
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	Table int32 `json:"table"`

	// NodeSelector selects which nodes this VRF applies to.
	// If nil or empty, the VRF applies to all nodes.
	//
	// +kubebuilder:validation:Optional
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector,omitempty"`

	// Selectors define which pods are members of this VRF.
	// Each selector can match pods by labels and/or namespace labels.
	//
	// +kubebuilder:validation:Required
	Selector VRFPodSelector `json:"selector"`

	// Interfaces is the list of network interface names bound to this VRF.
	//
	// If no interfaces are listed its assumed an underlying control plane is
	// configuring VRF membership for network interfaces.
	//
	// +kubebuilder:validation:Optional
	Interfaces []string `json:"interfaces,omitempty"`
}

// VRFNodeStatus represents the status of a single VRF on a particular node.
// Stored in the CiliumNode status, keyed by CiliumVRF CR name.
//
// +deepequal-gen=false
type VRFNodeStatus struct {
	// Conditions represent the latest available observations of this VRF's state on this node.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Condition types for VRF status on CiliumNode.
const (
	// VRFConditionReady indicates the VRF device has been created and
	// interfaces are bound.
	VRFConditionReady = "cilium.io/VRFReady"

	// VRFConditionInterfaceNotFound indicates one or more specified
	// interfaces were not found on the host.
	VRFConditionInterfaceNotFound = "cilium.io/InterfaceNotFound"

	// VRFConditionConflictingTableID indicates another CiliumVRF
	// already uses this routing table ID.
	VRFConditionConflictingTableID = "cilium.io/ConflictingTableID"

	// VRFConditionConflictingID indicates another CiliumVRF
	// already uses this VRF ID.
	VRFConditionConflictingID = "cilium.io/ConflictingID"

	// VRFConditionInterfaceFailure indicates a failure in configuring
	// the linux VRF device
	VRFConditionInterfaceFailure = "cilium.io/InterfaceFailure"

	// VRFConditionInvalidSelector indicates the VRF failed to be updated.
	VRFConditionUpdateFailure = "cilium.io/UpdateFailure"
)

// VRFPodSelector selects pods for VRF membership using label selectors.
type VRFPodSelector struct {
	// PodSelector selects pods by labels.
	// If present but empty, it selects all pods.
	//
	// +kubebuilder:validation:Optional
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`

	// NamespaceSelector selects namespaces using cluster-scoped labels.
	// If present but empty, it selects all namespaces.
	//
	// +kubebuilder:validation:Optional
	NamespaceSelector *slimv1.LabelSelector `json:"namespaceSelector,omitempty"`
}
