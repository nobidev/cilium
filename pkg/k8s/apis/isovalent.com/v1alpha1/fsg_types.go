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
// +kubebuilder:resource:categories={cilium,isovalent},singular="fabricsecuritygroup",path="fabricsecuritygroups",scope="Cluster",shortName={fsg}
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:JSONPath=".spec.endpointSelector",name="Endpoint Selector",type=string
// +deepequal-gen=false

// FabricSecurityGroup defines binding of Kubernetes resources to a fabric-level Security Group.
// Each object represents single fabric Security Group identified by metadata.name.
type FabricSecurityGroup struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec FabricSecurityGroupSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// FabricSecurityGroupList is a list of FabricSecurityGroup objects.
type FabricSecurityGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of FabricSecurityGroups.
	Items []FabricSecurityGroup `json:"items"`
}

// FabricSecurityGroupSpec defines binding of Kubernetes resources to the Fabric Security Group.
type FabricSecurityGroupSpec struct {
	// EndpointSelector selects Cilium endpoints bound to the fabric Security Group.
	//
	// +kubebuilder:validation:Required
	EndpointSelector *slimv1.LabelSelector `json:"endpointSelector,omitempty"`
}
