// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="clusterwideprivatenetwork",path="clusterwideprivatenetworks",scope="Cluster",shortName={icpn}
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +deepequal-gen=false

// ClusterwidePrivateNetwork defines a private network to which workloads can be attached.
type ClusterwidePrivateNetwork struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// The private network specification.
	//
	// +kubebuilder:validation:Required
	Spec PrivateNetworkSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// ClusterwidePrivateNetworkList is a list of ClusterwidePrivateNetwork objects.
type ClusterwidePrivateNetworkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of ClusterwidePrivateNetwork.
	Items []ClusterwidePrivateNetwork `json:"items"`
}

type PrivateNetworkSpec struct {
	// The list of Isovalent Network Bridges (INBs) serving this private network.
	// Currently, only a single INB per private network is supported, and
	// subsequent ones are ignored. This stanza shall be specified in the
	// main workload cluster(s) only, and not in the INB clusters.
	//
	// +kubebuilder:validation:Optional
	INBs []INBRef `json:"networkBridges,omitempty"`

	// The network interface providing external connectivity to this private
	// network. This stanza shall be specified in the Isovalent Network Bridge
	// cluster only.
	//
	// +kubebuilder:validation:Optional
	Interface InterfaceSpec `json:"interface"`

	// The set of routes configured for this private network.
	//
	// +kubebuilder:validation:Optional
	Routes []RouteSpec `json:"routes"`

	// The set of subnets (that is, L2 domains) associated with, and directly
	// reachable, from this private network.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Subnets []SubnetSpec `json:"subnets"`
}

type SubnetSpec struct {
	// The CIDR (either v4 or v6) associated with the private network.
	CIDR NetworkCIDR `json:"cidr"`
}

type INBRef struct {
	// The node IP of the Isovalent Network Bridge.
	IP IP `json:"ip"`
}

type InterfaceSpec struct {
	// The name of the network interface providing connectivity towards the
	// given private network. This field shall be specified in the Isovalent
	// Network Bridge cluster only.
	//
	// +kubebuilder:validation:Optional
	Name string `json:"name,omitempty"`
}
