// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent},singular="isovalentlb",path="isovalentlbs",scope="Namespaced",shortName={ilb}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

type IsovalentLB struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is a spec .
	//
	// +kubebuilder:validation:Required
	Spec IsovalentLBSpec `json:"spec"`

	// Status is a status .
	//
	// +kubebuilder:validation:Optional
	Status IsovalentLBStatus `json:"status,omitempty"`
}

type IsovalentLBSpec struct {
	// +kubebuilder:validation:Optional
	VIP *string `json:"vip,omitempty"`

	// +kubebuilder:validation:Required
	Port int32 `json:"port"`

	// +kubebuilder:validation:Required
	Backends []Backend `json:"backends"`

	// +kubebuilder:validation:Required
	Healthcheck Healthcheck `json:"healthcheck"`
}

type Backend struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=ip
	IP string `json:"ip"`
	// +kubebuilder:validation:Required
	Port int32 `json:"port"`
}

type Healthcheck struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=duration
	Interval string `json:"interval"`
}

type IsovalentLBStatus struct {
	// +kubebuilder:validation:Required
	Bar string `json:"bar"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +deepequal-gen=false

type IsovalentLBList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []IsovalentLB `json:"items"`
}
