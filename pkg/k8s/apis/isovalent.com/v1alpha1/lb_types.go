// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent,loadbalancer},singular="lbfrontend",path="lbfrontends",scope="Namespaced",shortName={lbfe}
// +kubebuilder:printcolumn:JSONPath=".spec.vipRef.name",name="VIP Reference",type=string
// +kubebuilder:printcolumn:JSONPath=".status.addresses.ipv4",name="VIP IPv4",type=string
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
	// +kubebuilder:validation:Required
	VIPRef LBFrontendVIPRef `json:"vipRef"`

	// +kubebuilder:validation:Required
	Port int32 `json:"port"`

	// +kubebuilder:validation:Required
	Applications LBFrontendApplications `json:"applications"`
}

// +kubebuilder:validation:XValidation:message="Exactly one application (httpProxy, httpsProxy or tlsPassthrough) must be specified",rule="(has(self.httpProxy) || has(self.httpsProxy) || has(self.tlsPassthrough)) && !(has(self.httpProxy) && has(self.httpsProxy)) && !(has(self.httpProxy) && has(self.tlsPassthrough)) && !(has(self.httpsProxy) && has(self.tlsPassthrough))"
type LBFrontendApplications struct {
	// +kubebuilder:validation:Optional
	HTTPProxy *LBFrontendApplicationHTTPProxy `json:"httpProxy,omitempty"`

	// +kubebuilder:validation:Optional
	HTTPSProxy *LBFrontendApplicationHTTPSProxy `json:"httpsProxy,omitempty"`

	// +kubebuilder:validation:Optional
	TLSPassthrough *LBFrontendApplicationTLSPassthrough `json:"tlsPassthrough,omitempty"`
}

type LBFrontendApplicationHTTPProxy struct {
	// +kubebuilder:validation:Optional
	HTTPConfig *LBFrontendHTTPConfig `json:"httpConfig,omitempty"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Routes []LBFrontendHTTPRoute `json:"routes"`
}

type LBFrontendApplicationHTTPSProxy struct {
	// +kubebuilder:validation:Optional
	HTTPConfig *LBFrontendHTTPConfig `json:"httpConfig,omitempty"`

	// +kubebuilder:validation:Optional
	TLSConfig *LBFrontendTLSConfig `json:"tlsConfig,omitempty"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Routes []LBFrontendHTTPRoute `json:"routes"`
}

// +kubebuilder:validation:XValidation:message="At least one http version must be enabled",rule="(has(self.enableHTTP11) && self.enableHTTP11) || (has(self.enableHTTP2) && self.enableHTTP2)"
type LBFrontendHTTPConfig struct {
	// +kubebuilder:validation:Optional
	EnableHTTP11 *bool `json:"enableHTTP11,omitempty"`

	// +kubebuilder:validation:Optional
	EnableHTTP2 *bool `json:"enableHTTP2,omitempty"`
}

type LBFrontendApplicationTLSPassthrough struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Routes []LBFrontendTLSPassthroughRoute `json:"routes"`
}

type LBFrontendTLSConfig struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Certificates []LBFrontendTLSCertificate `json:"certificates"`
}

// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^(\*\.)?[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
type LBFrontendHostName string

type LBFrontendTLSCertificate struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	SecretName string `json:"secretName"`
}

type LBFrontendHTTPRoute struct {
	// +kubebuilder:validation:Optional
	Match *LBFrontendHTTPRouteMatch `json:"match,omitempty"`

	// +kubebuilder:validation:Required
	BackendRef LBFrontendBackendRef `json:"backendRef"`
}

type LBFrontendHTTPRouteMatch struct {
	// +kubebuilder:validation:Optional
	HostNames []LBFrontendHostName `json:"hostNames,omitempty"`

	// +kubebuilder:validation:Optional
	Path *LBFrontendHTTPPath `json:"path,omitempty"`
}

// +kubebuilder:validation:XValidation:message="Exactly one path type (exact or prefix) must be specified",rule="(has(self.exact) || has(self.prefix)) && !(has(self.exact) && has(self.prefix))"
type LBFrontendHTTPPath struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	Exact *string `json:"exact,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	Prefix *string `json:"prefix,omitempty"`
}

type LBFrontendTLSPassthroughRoute struct {
	// +kubebuilder:validation:Optional
	Match *LBFrontendTLSPassthroughRouteMatch `json:"match"`

	// +kubebuilder:validation:Required
	BackendRef LBFrontendBackendRef `json:"backendRef"`
}

type LBFrontendTLSPassthroughRouteMatch struct {
	// +kubebuilder:validation:Optional
	HostNames []LBFrontendHostName `json:"hostNames,omitempty"`
}

type LBFrontendVIPRef struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

type LBFrontendBackendRef struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

type LBFrontendVIPAddresses struct {
	// +kubebuilder:validation:Optional
	IPv4 *string `json:"ipv4,omitempty"`
}

type LBFrontendStatus struct {
	// Allocated addresses copied from the LBVIP status. This is just for
	// displaying the allocated addresses in the kubectl get output.
	//
	// +kubebuilder:validation:Required
	Addresses LBFrontendVIPAddresses `json:"addresses"`

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
	ConditionTypeVIPExist      = "lb.cilium.io/VIPExist"
	ConditionTypeBackendsExist = "lb.cilium.io/BackendsExist"
	ConditionTypeSecretsExist  = "lb.cilium.io/SecretsExist"
)

const (
	IPAssignedConditionReasonIPPending  = "IPPending"
	IPAssignedConditionReasonIPAssigned = "IPAssigned"
)

const (
	VIPExistConditionReasonVIPExists  = "VIPExists"
	VIPExistConditionReasonVIPMissing = "VIPMissing"
)

const (
	BackendsExistConditionReasonAllBackendsExist = "AllBackendsExist"
	BackendsExistConditionReasonMissingBackends  = "MissingBackends"
)

const (
	SecretsExistConditionReasonAllSecretsExist = "AllSecretsExist"
	SecretsExistConditionReasonMissingSecrets  = "MissingSecrets"
)

const (
	ConditionTypeIPv4AddressAllocated = "lb.cilium.io/IPv4AddressAllocated"
)

const (
	IPv4AddressAllocatedConditionReasonAddressAlreadyInUse       = "AddressAlreadyInUse"
	IPv4AddressAllocatedConditionReasonAddressNoAvailableAddress = "NoAvailableAddress"
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
// +kubebuilder:resource:categories={cilium,isovalent,loadbalancer},singular="lbbackendpool",path="lbbackendpools",scope="Namespaced",shortName={lbbep}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

type LBBackendPool struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is a spec .
	//
	// +kubebuilder:validation:Required
	Spec LBBackendPoolSpec `json:"spec"`

	// Status is a status .
	//
	// +kubebuilder:validation:Optional
	Status LBBackendPoolStatus `json:"status,omitempty"`
}

type LBBackendPoolSpec struct {
	// +kubebuilder:validation:Required
	Addresses []Address `json:"addresses"`

	// +kubebuilder:validation:Required
	HealthCheck HealthCheck `json:"healthCheck"`

	// +kubebuilder:validation:Optional
	HTTPConfig *LBBackendHTTPConfig `json:"httpConfig,omitempty"`
}

type LBBackendHTTPConfig struct {
	// +kubebuilder:validation:Optional
	EnableHTTP11 *bool `json:"enableHTTP11,omitempty"`

	// +kubebuilder:validation:Optional
	EnableHTTP2 *bool `json:"enableHTTP2,omitempty"`
}

type Address struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=ip
	IP string `json:"ip"`
	// +kubebuilder:validation:Required
	Port int32 `json:"port"`
}

// +kubebuilder:validation:XValidation:message="Exactly one health check (HTTP or TCP) must be specified",rule="(has(self.tcp) || has(self.http)) && !(has(self.tcp) && has(self.http))"
type HealthCheck struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=30
	// +kubebuilder:validation:Minimum=1
	IntervalSeconds *int32 `json:"intervalSeconds,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=5
	// +kubebuilder:validation:Minimum=1
	TimeoutSeconds *int32 `json:"timeoutSeconds,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=1
	HealthyThreshold *int32 `json:"healthyThreshold,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=1
	UnhealthyThreshold *int32 `json:"unhealthyThreshold,omitempty"`

	// +kubebuilder:validation:Optional
	HTTP *HealthCheckHTTP `json:"http,omitempty"`

	// +kubebuilder:validation:Optional
	TCP *HealthCheckTCP `json:"tcp,omitempty"`
}

type HealthCheckHTTP struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=lb
	// +kubebuilder:validation:MinLength=1
	Host *string `json:"host,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=/healthz
	// +kubebuilder:validation:MinLength=1
	Path *string `json:"path,omitempty"`
}

type HealthCheckTCP struct{}

type LBBackendPoolStatus struct{}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +deepequal-gen=false

type LBBackendPoolList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []LBBackendPool `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent,loadbalancer},singular="lbvip",path="lbvips",scope="Namespaced",shortName={lbvip}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:printcolumn:JSONPath=".status.addresses.ipv4",name="IPv4",type=string
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

type LBVIP struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is a spec .
	//
	// +kubebuilder:validation:Required
	Spec LBVIPSpec `json:"spec"`

	// Status is a status .
	//
	// +kubebuilder:validation:Optional
	Status LBVIPStatus `json:"status,omitempty"`
}

type LBVIPSpec struct {
	// Desired IPv4 VIP. If the address is unspecified, it tries to
	// allocate available VIP from the pool. If address is specified, it
	// tries to allocate specified VIP from the pool.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=ipv4
	IPv4Request *string `json:"ipv4Request,omitempty"`
}

type LBVIPStatus struct {
	// Conditions describe the current conditions of the LBVIP.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Allocated addresses
	//
	// +kubebuilder:validation:Required
	Addresses LBVIPAddresses `json:"addresses"`
}

type LBVIPAddresses struct {
	// +kubebuilder:validation:Optional
	IPv4 *string `json:"ipv4,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +deepequal-gen=false

type LBVIPList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []LBVIP `json:"items"`
}
