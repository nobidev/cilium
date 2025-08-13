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

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="privatenetworkendpointslice",path="privatenetworkendpointslices",scope="Namespaced",shortName={ipnes}
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +deepequal-gen=false

// PrivateNetworkEndpointSlice contains the list of endpoints and their network mappings.
type PrivateNetworkEndpointSlice struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// The list of managed endpoints. Each entry contains the mapping of an
	// endpoint belonging to a given private network to the corresponding
	// identifiers in the main pod network.
	//
	// +kubebuilder:validation:Optional
	Endpoints []PrivateNetworkEndpointSliceEntry `json:"endpoints"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// PrivateNetworkEndpointSliceList is a list of PrivateNetworkEndpointSlice objects.
type PrivateNetworkEndpointSliceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of PrivateNetworkEndpointSlice.
	Items []PrivateNetworkEndpointSlice `json:"items"`
}

// +deepequal-gen=false
type PrivateNetworkEndpointSliceEntry struct {
	// The instant in time in which this entry was marked as active. If
	// multiple entries are advertized by different nodes and/or clusters for
	// the same private network endpoint, the latest that has been activated
	// takes precedence.
	//
	// +kubebuilder:validation:Optional
	ActivatedAt metav1.MicroTime `json:"activatedAt,omitzero"`

	// The endpoint identifiers from the pod network point of view.
	//
	// +kubebuilder:validation:Required
	Endpoint PrivateNetworkEndpointSliceEndpoint `json:"endpoint"`

	// The endpoint identifiers from the private network point of view.
	//
	// +kubebuilder:validation:Required
	Interface PrivateNetworkEndpointSliceInterface `json:"interface"`
}

// DeepEqual is implemented manually for PrivateNetworkEndpointSliceEntry, because metav1.MicroTime has no DeepEqual
func (in *PrivateNetworkEndpointSliceEntry) DeepEqual(other *PrivateNetworkEndpointSliceEntry) bool {
	if other == nil {
		return false
	}

	if !in.ActivatedAt.Equal(&other.ActivatedAt) {
		return false
	}

	if in.Endpoint != other.Endpoint {
		return false
	}

	if in.Interface != other.Interface {
		return false
	}

	return true
}

type PrivateNetworkEndpointSliceEndpoint struct {
	// The endpoint addresses (IPv4 and/or IPv6) from the pod network point
	// of view.
	//
	// +kubebuilder:validation:Required
	Addressing PrivateNetworkEndpointAddressing `json:"addressing"`

	// The name identifying the target endpoint.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

type PrivateNetworkEndpointSliceInterface struct {
	// The endpoint addresses (IPv4 and/or IPv6) from the private network point
	// of view.
	//
	// +kubebuilder:validation:Required
	Addressing PrivateNetworkEndpointAddressing `json:"addressing"`

	// The MAC address of the endpoint from the private network point of view.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=mac
	MAC string `json:"mac"`

	// Name of the target private network, as defined by a
	// ClusterwidePrivateNetwork resource.
	//
	// +kubebuilder:validation:Required
	Network string `json:"network"`
}

// +kubebuilder:validation:MinProperties=1
type PrivateNetworkEndpointAddressing struct {
	// The IPv4 endpoint address.
	//
	// +kubebuilder:validation:Format=ipv4
	IPv4 string `json:"ipv4,omitempty"`

	// The IPv6 endpoint address.
	//
	// +kubebuilder:validation:Format=ipv6
	IPv6 string `json:"ipv6,omitempty"`
}
