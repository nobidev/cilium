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

	// +kubebuilder:validation:Required
	Spec LBFrontendSpec `json:"spec"`

	// +kubebuilder:validation:Optional
	Status LBFrontendStatus `json:"status,omitempty"`
}

type LBFrontendSpec struct {
	// The reference to the LBVIP resource that the LBFrontend should be
	// associated with. The referred LBVIP must exist in the same namespace
	// as the frontend. Multiple LBFrontends can refer to the same LBVIP to
	// share the same VIP, but the port must be different.
	//
	// +kubebuilder:validation:Required
	VIPRef LBFrontendVIPRef `json:"vipRef"`

	// The port that this frontend should listen on.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// The configuration for the applications that running on the port.
	// While the name is plural, only one application can be specified
	// currently.
	//
	// +kubebuilder:validation:Required
	Applications LBFrontendApplications `json:"applications"`
}

// +kubebuilder:validation:XValidation:message="Exactly one application (httpProxy, httpsProxy or tlsPassthrough) must be specified",rule="(has(self.httpProxy) || has(self.httpsProxy) || has(self.tlsPassthrough)) && !(has(self.httpProxy) && has(self.httpsProxy)) && !(has(self.httpProxy) && has(self.tlsPassthrough)) && !(has(self.httpsProxy) && has(self.tlsPassthrough))"
type LBFrontendApplications struct {
	// Defining this stanza enables HTTPProxy application that proxies the
	// HTTP traffic to the backends over TCP connection.
	//
	// +kubebuilder:validation:Optional
	HTTPProxy *LBFrontendApplicationHTTPProxy `json:"httpProxy,omitempty"`

	// Defining this stanza enables HTTPSProxy application that proxies the
	// HTTPS traffic to the backends over TLS and TCP connections.
	//
	// +kubebuilder:validation:Optional
	HTTPSProxy *LBFrontendApplicationHTTPSProxy `json:"httpsProxy,omitempty"`

	// Defining this stanza enables TLSPassthrough application that proxies
	// the TLS traffic without terminating the TLS connection.
	//
	// +kubebuilder:validation:Optional
	TLSPassthrough *LBFrontendApplicationTLSPassthrough `json:"tlsPassthrough,omitempty"`
}

type LBFrontendApplicationHTTPProxy struct {
	// The application-wide HTTP configuration.
	//
	// +kubebuilder:validation:Optional
	HTTPConfig *LBFrontendHTTPConfig `json:"httpConfig,omitempty"`

	// The HTTP routing configuration.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Routes []LBFrontendHTTPRoute `json:"routes"`
}

type LBFrontendApplicationHTTPSProxy struct {
	// The application-wide HTTP configuration.
	//
	// +kubebuilder:validation:Optional
	HTTPConfig *LBFrontendHTTPConfig `json:"httpConfig,omitempty"`

	// The application-wide TLS configuration.
	//
	// +kubebuilder:validation:Optional
	TLSConfig *LBFrontendTLSConfig `json:"tlsConfig,omitempty"`

	// The HTTP routing configuration.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Routes []LBFrontendHTTPRoute `json:"routes"`
}

// +kubebuilder:validation:XValidation:message="At least one http version must be enabled",rule="(has(self.enableHTTP11) && self.enableHTTP11) || (has(self.enableHTTP2) && self.enableHTTP2)"
type LBFrontendHTTPConfig struct {
	// Setting this to true enables HTTP/1.1.
	//
	// +kubebuilder:validation:Optional
	EnableHTTP11 *bool `json:"enableHTTP11,omitempty"`

	// Setting this to true enables HTTP2.
	//
	// +kubebuilder:validation:Optional
	EnableHTTP2 *bool `json:"enableHTTP2,omitempty"`
}

type LBFrontendApplicationTLSPassthrough struct {
	// The TLS passthrough routing configuration.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Routes []LBFrontendTLSPassthroughRoute `json:"routes"`
}

type LBFrontendTLSConfig struct {
	// The list of certificates that the frontend uses.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Certificates []LBFrontendTLSCertificate `json:"certificates"`

	// Minimum TLS version.
	//
	// If not defined, the defaults of the Envoy proxy are used.
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-tlsparameters
	//
	// +kubebuilder:validation:Optional
	MinTLSVersion *LBFrontendTLSProtocolVersion `json:"minTLSVersion,omitempty"`

	// Maximum TLS version.
	//
	// If not defined, the defaults of the Envoy proxy are used.
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-tlsparameters
	//
	// +kubebuilder:validation:Optional
	MaxTLSVersion *LBFrontendTLSProtocolVersion `json:"maxTLSVersion,omitempty"`

	// Allowed TLS cipher suites.
	//
	// If not defined, the defaults of the Envoy proxy are used.
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-tlsparameters
	//
	// +kubebuilder:validation:Optional
	AllowedCipherSuites []LBFrontendTLSCipherSuite `json:"allowedCipherSuites,omitempty"`

	// Allowed ECDH Curves.
	//
	// If not defined, the defaults of the Envoy proxy are used.
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-tlsparameters
	//
	// +kubebuilder:validation:Optional
	AllowedECDHCurves []LBFrontendTLSECDHCurve `json:"allowedECDHCurves,omitempty"`

	// Allowed signature algorithms. The list is ordered by preference.
	//
	// If not defined, the defaults of the Envoy proxy are used.
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-tlsparameters
	//
	// +kubebuilder:validation:Optional
	AllowedSignatureAlgorithms []LBFrontendTLSSignatureAlgorithm `json:"allowedSignatureAlgorithms,omitempty"`
}

// +kubebuilder:validation:Enum=TLSv1_0;TLSv1_1;TLSv1_2;TLSv1_3
type LBFrontendTLSProtocolVersion string

// +kubebuilder:validation:MinLength=1
type LBFrontendTLSCipherSuite string

// +kubebuilder:validation:MinLength=1
type LBFrontendTLSECDHCurve string

// +kubebuilder:validation:MinLength=1
type LBFrontendTLSSignatureAlgorithm string

// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^(\*\.)?[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
type LBFrontendHostName string

type LBFrontendTLSCertificate struct {
	// The name of the k8s secret that contains the certificate and the
	// private key. The secret type must be kubernetes.io/tls and the
	// format must follow the spec.
	//
	// https://kubernetes.io/docs/concepts/configuration/secret/#tls-secrets
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	SecretName string `json:"secretName"`
}

type LBFrontendHTTPRoute struct {
	// The HTTP route matching criteria. All conditions must be satisfied
	// for the route to be matched.
	//
	// +kubebuilder:validation:Optional
	Match *LBFrontendHTTPRouteMatch `json:"match,omitempty"`

	// The reference to the LBBackendPool resource that this route should
	// forward the traffic to when the route is matched. The referred
	// LBBackendPool must exist in the same namespace as the LBFrontend.
	//
	// +kubebuilder:validation:Required
	BackendRef LBFrontendBackendRef `json:"backendRef"`
}

type LBFrontendHTTPRouteMatch struct {
	// The list of host names that the route should match. The host name is
	// the value of the Host header in the HTTP request for plain-text
	// HTTP. When TLS is enabled, the host name must match both the SNI and
	// the Host header. The following formats are supported:
	//
	// - Exact domain names: www.example.com
	//
	// - Suffix domain wildcards: *.example.com or *-bar.example.com
	//
	// - Prefix domain wildcards: foo.* or foo-*.
	//
	// - Special wildcard: * matching any domain
	//
	// Omitting this field is identical to specifying a wildcard "*".
	//
	// +kubebuilder:validation:Optional
	HostNames []LBFrontendHostName `json:"hostNames,omitempty"`

	// The path matching criteria. When omitted, the route matches all
	// paths.
	//
	// +kubebuilder:validation:Optional
	Path *LBFrontendHTTPPath `json:"path,omitempty"`
}

// +kubebuilder:validation:XValidation:message="Exactly one path type (exact or prefix) must be specified",rule="(has(self.exact) || has(self.prefix)) && !(has(self.exact) && has(self.prefix))"
type LBFrontendHTTPPath struct {
	// Exact matching. The path must be exactly the same as the value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	Exact *string `json:"exact,omitempty"`

	// Prefix matching. The path must start with the value.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	Prefix *string `json:"prefix,omitempty"`
}

type LBFrontendTLSPassthroughRoute struct {
	// The TLS route matching criteria. All conditions must be satisfied
	// for the route to be matched.
	//
	// +kubebuilder:validation:Optional
	Match *LBFrontendTLSPassthroughRouteMatch `json:"match"`

	// The reference to the LBBackendPool resource that this route should
	// forward the traffic to when the route is matched. The referred
	// LBBackendPool must exist in the same namespace as the LBFrontend.
	//
	// +kubebuilder:validation:Required
	BackendRef LBFrontendBackendRef `json:"backendRef"`
}

type LBFrontendTLSPassthroughRouteMatch struct {
	// The list of host names that the route should match. The host name is
	// the value of the Host header in the HTTP request for plain-text
	// HTTP. When TLS is enabled, the host name must match both the SNI and
	// the Host header. The following formats are supported:
	//
	// - Exact domain names: www.example.com
	//
	// - Suffix domain wildcards: *.example.com or *-bar.example.com
	//
	// - Prefix domain wildcards: foo.* or foo-*.
	//
	// - Special wildcard: * matching any domain
	//
	// Omitting this field is identical to specifying a wildcard "*".
	//
	// +kubebuilder:validation:Optional
	HostNames []LBFrontendHostName `json:"hostNames,omitempty"`
}

type LBFrontendVIPRef struct {
	// The name of the LBVIP resource.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

type LBFrontendBackendRef struct {
	// The name of the LBBackendPool resource.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

type LBFrontendVIPAddresses struct {
	// IPv4 VIP assigned to the LBFrontend.
	//
	// +kubebuilder:validation:Optional
	IPv4 *string `json:"ipv4,omitempty"`
}

type LBFrontendStatus struct {
	// Allocated addresses for the LBFrontend. The value is copied from the
	// LBVIP's status that the frontend refers to. This field exists for
	// the cosmetic purpose of showing the VIP in the kubectl output. You
	// should use LBVIP's status field as the source of truth.
	//
	// +kubebuilder:validation:Required
	Addresses LBFrontendVIPAddresses `json:"addresses"`

	// The current conditions of the LBFrontend.
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

	// +kubebuilder:validation:Required
	Spec LBBackendPoolSpec `json:"spec"`

	// +kubebuilder:validation:Optional
	Status LBBackendPoolStatus `json:"status,omitempty"`
}

type LBBackendPoolSpec struct {
	// The list of backends included in the pool.
	//
	// +kubebuilder:validation:Required
	Backends []Backend `json:"backends"`

	// The pool-wide health check configuration.
	//
	// +kubebuilder:validation:Required
	HealthCheck HealthCheck `json:"healthCheck"`

	// The pool-wide HTTP configuration.
	//
	// +kubebuilder:validation:Optional
	HTTPConfig *LBBackendHTTPConfig `json:"httpConfig,omitempty"`
}

type LBBackendHTTPConfig struct {
	// Setting this to true enables HTTP/1.1.
	//
	// +kubebuilder:validation:Optional
	EnableHTTP11 *bool `json:"enableHTTP11,omitempty"`

	// Setting this to true enables HTTP2.
	//
	// +kubebuilder:validation:Optional
	EnableHTTP2 *bool `json:"enableHTTP2,omitempty"`
}

type Backend struct {
	// The IP address of the backend.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=ip
	IP string `json:"ip"`
	// The port that the backend listens on.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// +kubebuilder:validation:XValidation:message="Exactly one health check (HTTP or TCP) must be specified",rule="(has(self.tcp) || has(self.http)) && !(has(self.tcp) && has(self.http))"
type HealthCheck struct {
	// The interval between health check probes.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=30
	// +kubebuilder:validation:Minimum=1
	IntervalSeconds *int32 `json:"intervalSeconds,omitempty"`

	// The timeout for each health check probe.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=5
	// +kubebuilder:validation:Minimum=1
	TimeoutSeconds *int32 `json:"timeoutSeconds,omitempty"`

	// The number of consecutive successful health check probes required
	// before considering the backend healthy.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=1
	HealthyThreshold *int32 `json:"healthyThreshold,omitempty"`

	// The number of consecutive failed health check probes required before
	// considering the backend unhealthy.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=1
	UnhealthyThreshold *int32 `json:"unhealthyThreshold,omitempty"`

	// The HTTP health check configuration. Exactly one of http or tcp must
	// be specified.
	//
	// +kubebuilder:validation:Optional
	HTTP *HealthCheckHTTP `json:"http,omitempty"`

	// The TCP health check configuration. Exactly one of http or tcp must
	// be specified.
	//
	// +kubebuilder:validation:Optional
	TCP *HealthCheckTCP `json:"tcp,omitempty"`
}

type HealthCheckHTTP struct {
	// The host name to use in the HTTP health checking probe. When
	// omitted, the probe uses "lb".
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=lb
	// +kubebuilder:validation:MinLength=1
	Host *string `json:"host,omitempty"`

	// The path to use in the HTTP health checking probe. When omitted, the
	// probe uses "/healthz".
	//
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

	// +kubebuilder:validation:Required
	Spec LBVIPSpec `json:"spec"`

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
	// The current conditions of the LBVIP.
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
	// The allocated IPv4 VIP.
	//
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
