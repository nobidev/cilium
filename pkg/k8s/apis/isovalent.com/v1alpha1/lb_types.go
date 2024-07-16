// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent,loadbalancer},singular="lbfrontend",path="lbfrontends",scope="Namespaced",shortName={lbfe}
// +kubebuilder:printcolumn:JSONPath=".spec.vip",name="Requested VIP",type=string
// +kubebuilder:printcolumn:JSONPath=".status.vip",name="Assigned VIP",type=string
// +kubebuilder:printcolumn:JSONPath=".spec.port",name="Port",type=string
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

type LBFrontend struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is a spec .
	//
	// +kubebuilder:validation:Required
	Spec LBFrontendSpec `json:"spec"`

	// Status is a status .
	//
	// +kubebuilder:validation:Optional
	Status LBFrontendStatus `json:"status,omitempty"`
}

type LBFrontendSpec struct {
	// +kubebuilder:validation:Optional
	VIP *string `json:"vip,omitempty"`

	// +kubebuilder:validation:Required
	Port int32 `json:"port"`

	// +kubebuilder:validation:Required
	Applications LBFrontendApplications `json:"applications"`
}

type LBFrontendApplications struct {
	// +kubebuilder:validation:Optional
	HTTPProxy *LBFrontendApplicationHTTPProxy `json:"httpProxy,omitempty"`

	// +kubebuilder:validation:Optional
	HTTPSProxy *LBFrontendApplicationHTTPSProxy `json:"httpsProxy,omitempty"`

	// +kubebuilder:validation:Optional
	TLSPassthrough *LBFrontendApplicationTLSPassthrough `json:"tlsPassthrough,omitempty"`
}

type LBFrontendApplicationHTTPProxy struct {
	// +kubebuilder:validation:Required
	Routes []LBFrontendHTTPRoute `json:"routes"`
}

type LBFrontendApplicationHTTPSProxy struct {
	// +kubebuilder:validation:Optional
	TLSConfig *LBFrontendTLSConfig `json:"tlsConfig,omitempty"`

	// +kubebuilder:validation:Required
	Routes []LBFrontendHTTPRoute `json:"routes"`
}

type LBFrontendApplicationTLSPassthrough struct {
	// +kubebuilder:validation:Required
	Routes []LBFrontendTLSPassthroughRoute `json:"routes"`
}

type LBFrontendTLSConfig struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Certificates []LBFrontendTLSCertificate `json:"certificates"`
}

// +kubebuilder:validation:MinLength=1
type LBFrontendHostName string

type LBFrontendTLSCertificate struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	SecretName string `json:"secretName"`
}

type LBFrontendHTTPRoute struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	HostNames []LBFrontendHostName `json:"hostNames"`

	// +kubebuilder:validation:Optional
	Path *LBFrontendHTTPPath `json:"path,omitempty"`

	// +kubebuilder:validation:Required
	BackendRef LBFrontendBackendRef `json:"backendRef"`
}

type LBFrontendHTTPPath struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	Exact *string `json:"exact,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	Prefix *string `json:"prefix,omitempty"`
}

type LBFrontendTLSPassthroughRoute struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	HostNames []LBFrontendHostName `json:"hostNames"`

	// +kubebuilder:validation:Required
	BackendRef LBFrontendBackendRef `json:"backendRef"`
}

type LBFrontendBackendRef struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

type LBFrontendStatus struct {
	// VIP is the VIP that is assigned to the loadbalancer frontend.
	//
	// +kubebuilder:validation:Required
	VIP string `json:"vip"`

	// Conditions describe the current conditions of the LBFrontend.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

const (
	ConditionTypeIPAssigned    = "lb.cilium.io/IPAssigned"
	ConditionTypeBackendsExist = "lb.cilium.io/BackendsExist"
	ConditionTypeSecretsExist  = "lb.cilium.io/SecretsExist"
)

const (
	IPAssignedConditionReasonIPPending  = "IPPending"
	IPAssignedConditionReasonIPAssigned = "IPAssigned"
)

const (
	BackendsExistConditionReasonAllBackendsExist = "AllBackendsExist"
	BackendsExistConditionReasonMissingBackends  = "MissingBackends"
)

const (
	SecretsExistConditionReasonAllSecretsExist = "AllSecretsExist"
	SecretsExistConditionReasonMissingSecrets  = "MissingSecrets"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +deepequal-gen=false

type LBFrontendList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []LBFrontend `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent,loadbalancer},singular="lbbackend",path="lbbackends",scope="Namespaced",shortName={lbbe}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

type LBBackend struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is a spec .
	//
	// +kubebuilder:validation:Required
	Spec LBBackendSpec `json:"spec"`

	// Status is a status .
	//
	// +kubebuilder:validation:Optional
	Status LBBackendStatus `json:"status,omitempty"`
}

type LBBackendSpec struct {
	// +kubebuilder:validation:Required
	Addresses []Address `json:"addresses"`

	// +kubebuilder:validation:Required
	Healthcheck Healthcheck `json:"healthcheck"`
}

type Address struct {
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

type LBBackendStatus struct{}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +deepequal-gen=false

type LBBackendList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []LBBackend `json:"items"`
}
