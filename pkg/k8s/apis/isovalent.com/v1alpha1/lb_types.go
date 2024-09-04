// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent,loadbalancer},singular="lbservice",path="lbservices",scope="Namespaced",shortName={lbsvc}
// +kubebuilder:printcolumn:JSONPath=".spec.vipRef.name",name="VIP Reference",type=string
// +kubebuilder:printcolumn:JSONPath=".status.addresses.ipv4",name="VIP IPv4",type=string
// +kubebuilder:printcolumn:JSONPath=".spec.port",name="Port",type=string
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

type LBService struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec LBServiceSpec `json:"spec"`

	// +kubebuilder:validation:Optional
	Status LBServiceStatus `json:"status,omitempty"`
}

type LBServiceSpec struct {
	// The reference to the LBVIP resource that the LBService should be
	// associated with. The referred LBVIP must exist in the same namespace
	// as the service. Multiple LBServices can refer to the same LBVIP to
	// share the same VIP, but the port must be different.
	//
	// +kubebuilder:validation:Required
	VIPRef LBServiceVIPRef `json:"vipRef"`

	// The port that this service should listen on.
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
	Applications LBServiceApplications `json:"applications"`
}

// +kubebuilder:validation:XValidation:message="Exactly one application (httpProxy, httpsProxy or tlsPassthrough) must be specified", rule="(has(self.httpProxy) || has(self.httpsProxy) || has(self.tlsPassthrough) || has(self.tlsProxy)) && !(has(self.httpProxy) && has(self.httpsProxy)) && !(has(self.httpProxy) && has(self.tlsPassthrough)) && !(has(self.httpProxy) && has(self.tlsProxy)) && !(has(self.httpsProxy) && has(self.tlsPassthrough)) && !(has(self.httpsProxy) && has(self.tlsProxy)) && !(has(self.tlsPassthrough) && has(self.tlsProxy))"
type LBServiceApplications struct {
	// Defining this stanza enables HTTPProxy application that proxies the
	// HTTP traffic to the backends over TCP connection.
	//
	// +kubebuilder:validation:Optional
	HTTPProxy *LBServiceApplicationHTTPProxy `json:"httpProxy,omitempty"`

	// Defining this stanza enables HTTPSProxy application that proxies the
	// HTTPS traffic to the backends over TLS and TCP connections.
	//
	// +kubebuilder:validation:Optional
	HTTPSProxy *LBServiceApplicationHTTPSProxy `json:"httpsProxy,omitempty"`

	// Defining this stanza enables TLSPassthrough application that proxies
	// the TLS traffic without terminating the TLS connection.
	//
	// +kubebuilder:validation:Optional
	TLSPassthrough *LBServiceApplicationTLSPassthrough `json:"tlsPassthrough,omitempty"`

	// Defining this stanza enables TLSProxy application that proxies the
	// TLS traffic to the backends by terminating the TLS.
	//
	// +kubebuilder:validation:Optional
	TLSProxy *LBServiceApplicationTLSProxy `json:"tlsProxy,omitempty"`
}

type LBServiceApplicationHTTPProxy struct {
	// The application-wide HTTP configuration.
	//
	// +kubebuilder:validation:Optional
	HTTPConfig *LBServiceHTTPConfig `json:"httpConfig,omitempty"`

	// The HTTP routing configuration.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Routes []LBServiceHTTPRoute `json:"routes"`
}

type LBServiceApplicationHTTPSProxy struct {
	// The application-wide HTTP configuration.
	//
	// +kubebuilder:validation:Optional
	HTTPConfig *LBServiceHTTPConfig `json:"httpConfig,omitempty"`

	// The application-wide TLS configuration.
	//
	// +kubebuilder:validation:Optional
	TLSConfig *LBServiceTLSConfig `json:"tlsConfig,omitempty"`

	// The HTTP routing configuration.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Routes []LBServiceHTTPRoute `json:"routes"`
}

// +kubebuilder:validation:XValidation:message="At least one http version must be enabled",rule="(has(self.enableHTTP11) && self.enableHTTP11) || (has(self.enableHTTP2) && self.enableHTTP2)"
type LBServiceHTTPConfig struct {
	// Setting this to true enables HTTP/1.1.
	//
	// +kubebuilder:validation:Optional
	EnableHTTP11 *bool `json:"enableHTTP11,omitempty"`

	// Setting this to true enables HTTP2.
	//
	// +kubebuilder:validation:Optional
	EnableHTTP2 *bool `json:"enableHTTP2,omitempty"`
}

type LBServiceApplicationTLSPassthrough struct {
	// The TLS passthrough routing configuration.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Routes []LBServiceTLSPassthroughRoute `json:"routes"`
}

type LBServiceApplicationTLSProxy struct {
	// The application-wide TLS configuration.
	//
	// +kubebuilder:validation:Optional
	TLSConfig *LBServiceTLSConfig `json:"tlsConfig,omitempty"`

	// The TLS proxy routing configuration.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Routes []LBServiceTLSRoute `json:"routes"`
}

type LBServiceTLSConfig struct {
	// The list of certificates that the service uses.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Certificates []LBServiceTLSCertificate `json:"certificates"`

	// Optional certificate verification.
	//
	// +kubebuilder:validation:Optional
	Validation *LBTLSValidationConfig `json:"validation,omitempty"`

	// Minimum TLS version.
	//
	// If not defined, the defaults of the Envoy proxy are used.
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-tlsparameters
	//
	// +kubebuilder:validation:Optional
	MinTLSVersion *LBTLSProtocolVersion `json:"minTLSVersion,omitempty"`

	// Maximum TLS version.
	//
	// If not defined, the defaults of the Envoy proxy are used.
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-tlsparameters
	//
	// +kubebuilder:validation:Optional
	MaxTLSVersion *LBTLSProtocolVersion `json:"maxTLSVersion,omitempty"`

	// Allowed TLS cipher suites.
	//
	// If not defined, the defaults of the Envoy proxy are used.
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-tlsparameters
	//
	// +kubebuilder:validation:Optional
	AllowedCipherSuites []LBTLSCipherSuite `json:"allowedCipherSuites,omitempty"`

	// Allowed ECDH Curves.
	//
	// If not defined, the defaults of the Envoy proxy are used.
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-tlsparameters
	//
	// +kubebuilder:validation:Optional
	AllowedECDHCurves []LBTLSECDHCurve `json:"allowedECDHCurves,omitempty"`

	// Allowed signature algorithms. The list is ordered by preference.
	//
	// If not defined, the defaults of the Envoy proxy are used.
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto#extensions-transport-sockets-tls-v3-tlsparameters
	//
	// +kubebuilder:validation:Optional
	AllowedSignatureAlgorithms []LBTLSSignatureAlgorithm `json:"allowedSignatureAlgorithms,omitempty"`
}

type LBTLSValidationConfig struct {
	// The k8s secret that contains the trusted CA in the secret data field `ca.crt`.
	//
	// +kubebuilder:validation:Required
	SecretRef LBServiceSecretRef `json:"secretRef"`

	// Allowed subject alternative names
	//
	// +kubebuilder:validation:Optional
	SubjectAlternativeNames []LBTLSValidationConfigSAN `json:"subjectAlternativeNames,omitempty"`
}

type LBTLSValidationConfigSAN struct {
	// Exact matching. The SAN must be exactly the same as the value.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Exact string `json:"exact"`
}

type LBServiceSecretRef struct {
	// The name of the K8s Secret resource.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// +kubebuilder:validation:Enum=TLSv1_0;TLSv1_1;TLSv1_2;TLSv1_3
type LBTLSProtocolVersion string

// +kubebuilder:validation:MinLength=1
type LBTLSCipherSuite string

// +kubebuilder:validation:MinLength=1
type LBTLSECDHCurve string

// +kubebuilder:validation:MinLength=1
type LBTLSSignatureAlgorithm string

// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^(\*\.)?[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
type LBServiceHostName string

type LBServiceTLSCertificate struct {
	// Reference to K8s secret in the same namespace that contains
	// the certificate and the private key that the service uses.
	//
	// The secret type must be kubernetes.io/tls and the
	// format must follow the spec.
	//
	// https://kubernetes.io/docs/concepts/configuration/secret/#tls-secrets
	// +kubebuilder:validation:Required
	SecretRef LBServiceSecretRef `json:"secretRef"`
}

type LBServiceHTTPRoute struct {
	// The HTTP route matching criteria. All conditions must be satisfied
	// for the route to be matched.
	//
	// +kubebuilder:validation:Optional
	Match *LBServiceHTTPRouteMatch `json:"match,omitempty"`

	// The reference to the LBBackendPool resource that this route should
	// forward the traffic to when the route is matched. The referred
	// LBBackendPool must exist in the same namespace as the LBService.
	//
	// +kubebuilder:validation:Required
	BackendRef LBServiceBackendRef `json:"backendRef"`

	// The optional persistent backend configuration for this HTTP route.
	// It defines the request attributes that should be obtained to decide
	// whether requests should be sent to persistently the same backend.
	// The attributes are logically ANDed.
	//
	// Note: Persistent backend configuration is only supported by LBBackendPools
	// with loadbalancing algorithm `consistentHashing`.
	//
	// +kubebuilder:validation:Optional
	PersistentBackend *LBServiceHTTPRoutePersistentBackend `json:"persistentBackend,omitempty"`
}

// +kubebuilder:validation:XValidation:message="At least one attribute must be configured",rule="(has(self.sourceIP) || size(self.cookies) > 0 || size(self.headers) > 0)"
type LBServiceHTTPRoutePersistentBackend struct {
	// Whether requests from the same source IP should be sent to
	// the same backend.
	//
	// +kubebuilder:validation:Optional
	SourceIP *bool `json:"sourceIP,omitempty"`

	// List of cookies for which requests are sent to the same backend if they match.
	//
	// +kubebuilder:validation:Optional
	Cookies []LBServiceHTTPRoutePersistentBackendCookie `json:"cookies,omitempty"`

	// List of headers for which requests are sent to the same backend if they match.
	//
	// +kubebuilder:validation:Optional
	Headers []LBServiceHTTPRoutePersistentBackendHeader `json:"headers,omitempty"`
}

type LBServiceHTTPRoutePersistentBackendCookie struct {
	// The name of the cookie that will be used to obtain the hash key.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

type LBServiceHTTPRoutePersistentBackendHeader struct {
	// The name of the header that will be used to obtain the hash key.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

type LBServiceHTTPRouteMatch struct {
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
	HostNames []LBServiceHostName `json:"hostNames,omitempty"`

	// The path matching criteria. When omitted, the route matches all
	// paths.
	//
	// +kubebuilder:validation:Optional
	Path *LBServiceHTTPPath `json:"path,omitempty"`
}

// +kubebuilder:validation:XValidation:message="Exactly one path type (exact or prefix) must be specified",rule="(has(self.exact) || has(self.prefix)) && !(has(self.exact) && has(self.prefix))"
type LBServiceHTTPPath struct {
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

type LBServiceTLSPassthroughRoute struct {
	// The TLS route matching criteria. All conditions must be satisfied
	// for the route to be matched.
	//
	// +kubebuilder:validation:Optional
	Match *LBServiceTLSPassthroughRouteMatch `json:"match"`

	// The reference to the LBBackendPool resource that this route should
	// forward the traffic to when the route is matched. The referred
	// LBBackendPool must exist in the same namespace as the LBService.
	//
	// +kubebuilder:validation:Required
	BackendRef LBServiceBackendRef `json:"backendRef"`

	// The optional persistent backend configuration for this TLS passthrough route.
	// It defines the request attributes that should be obtained to decide
	// whether requests should be sent to persistently the same backend.
	// The attributes are logically ANDed.
	//
	// Note: Persistent backend configuration is only supported by LBBackendPools
	// with loadbalancing algorithm `consistentHashing`.
	//
	// +kubebuilder:validation:Optional
	PersistentBackend *LBServiceTLSRoutePersistentBackend `json:"persistentBackend,omitempty"`
}

type LBServiceTLSRoute struct {
	// The TLS route matching criteria. All conditions must be satisfied
	// for the route to be matched.
	//
	// +kubebuilder:validation:Optional
	Match *LBServiceTLSRouteMatch `json:"match"`

	// The reference to the LBBackendPool resource that this route should
	// forward the traffic to when the route is matched. The referred
	// LBBackendPool must exist in the same namespace as the LBService.
	//
	// +kubebuilder:validation:Required
	BackendRef LBServiceBackendRef `json:"backendRef"`

	// The optional persistent backend configuration for this TLS proxy route.
	// It defines the request attributes that should be obtained to decide
	// whether requests should be sent to persistently the same backend.
	// The attributes are logically ANDed.
	//
	// Note: Persistent backend configuration is only supported by LBBackendPools
	// with loadbalancing algorithm `consistentHashing`.
	//
	// +kubebuilder:validation:Optional
	PersistentBackend *LBServiceTLSRoutePersistentBackend `json:"persistentBackend,omitempty"`
}

type LBServiceTLSPassthroughRouteMatch struct {
	// The list of host names that the route should match. The host name
	// must match the SNI. The following formats are supported:
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
	HostNames []LBServiceHostName `json:"hostNames,omitempty"`
}

type LBServiceTLSRouteMatch struct {
	// The list of host names that the route should match. The host name
	// must match the SNI. The following formats are supported:
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
	HostNames []LBServiceHostName `json:"hostNames,omitempty"`
}

// +kubebuilder:validation:XValidation:message="At least one attribute must be configured",rule="(has(self.sourceIP))"
type LBServiceTLSRoutePersistentBackend struct {
	// Whether requests from the same source IP should be sent to
	// the same backend.
	//
	// +kubebuilder:validation:Optional
	SourceIP *bool `json:"sourceIP,omitempty"`
}

type LBServiceVIPRef struct {
	// The name of the LBVIP resource.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

type LBServiceBackendRef struct {
	// The name of the LBBackendPool resource.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

type LBServiceVIPAddresses struct {
	// IPv4 VIP assigned to the LBService.
	//
	// +kubebuilder:validation:Optional
	IPv4 *string `json:"ipv4,omitempty"`
}

type LBServiceStatus struct {
	// Allocated addresses for the LBService. The value is copied from the
	// LBVIP's status that the service refers to. This field exists for
	// the cosmetic purpose of showing the VIP in the kubectl output. You
	// should use LBVIP's status field as the source of truth.
	//
	// +kubebuilder:validation:Required
	Addresses LBServiceVIPAddresses `json:"addresses"`

	// The current conditions of the LBService.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

const (
	ConditionTypeIPAssigned         = "lb.cilium.io/IPAssigned"
	ConditionTypeVIPExist           = "lb.cilium.io/VIPExist"
	ConditionTypeBackendsExist      = "lb.cilium.io/BackendsExist"
	ConditionTypeBackendsCompatible = "lb.cilium.io/BackendsCompatible"
	ConditionTypeSecretsExist       = "lb.cilium.io/SecretsExist"
)

const (
	IPAssignedConditionReasonIPFailure  = "IPFailure"
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
	BackendsCompatibleConditionReasonAllBackendsCompatible = "AllBackendsCompatible"
	BackendsCompatibleConditionReasonIncompatibleBackends  = "IncompatibleBackends"
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
	IPv4AddressAllocatedConditionReasonAddressNoPool             = "NoPool"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +deepequal-gen=false

type LBServiceList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []LBService `json:"items"`
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

	// The pool-wide loadbalancing configuration.
	//
	// +kubebuilder:validation:Optional
	Loadbalancing *Loadbalancing `json:"loadbalancing,omitempty"`

	// The pool-wide TCP configuration.
	//
	// +kubebuilder:validation:Optional
	TCPConfig *LBBackendTCPConfig `json:"tcpConfig,omitempty"`

	// The pool-wide TLS configuration.
	//
	// +kubebuilder:validation:Optional
	TLSConfig *LBBackendTLSConfig `json:"tlsConfig,omitempty"`

	// The pool-wide HTTP configuration.
	//
	// +kubebuilder:validation:Optional
	HTTPConfig *LBBackendHTTPConfig `json:"httpConfig,omitempty"`
}

type LBBackendTCPConfig struct {
	// The connect timeout for the connections.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	ConnectTimeoutSeconds *int32 `json:"connectTimeoutSeconds,omitempty"`
}

type LBBackendTLSConfig struct {
	// Minimum TLS version.
	//
	// +kubebuilder:validation:Optional
	MinTLSVersion *LBTLSProtocolVersion `json:"minTLSVersion,omitempty"`

	// Maximum TLS version.
	//
	// +kubebuilder:validation:Optional
	MaxTLSVersion *LBTLSProtocolVersion `json:"maxTLSVersion,omitempty"`

	// Allowed TLS cipher suites.
	//
	// +kubebuilder:validation:Optional
	AllowedCipherSuites []LBTLSCipherSuite `json:"allowedCipherSuites,omitempty"`

	// Allowed ECDH Curves.
	//
	// +kubebuilder:validation:Optional
	AllowedECDHCurves []LBTLSECDHCurve `json:"allowedECDHCurves,omitempty"`

	// Allowed signature algorithms. The list is ordered by preference.
	//
	// +kubebuilder:validation:Optional
	AllowedSignatureAlgorithms []LBTLSSignatureAlgorithm `json:"allowedSignatureAlgorithms,omitempty"`
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

	// The weight of that backend. Used by loadbalancing algorithms.
	//
	// The weight for a backend is divided by the sum
	// of the weights of all backends in the backendpool
	// to produce a percentage of traffic for the backend.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	Weight *uint32 `json:"weight,omitempty"`

	// The status of that backend.
	//
	// If not defined, active health checking is used to determione the
	// status of the backend.
	//
	// +kubebuilder:validation:Optional
	Status *BackendStatus `json:"status,omitempty"`
}

// +kubebuilder:validation:Enum=Draining
type BackendStatus string

const (
	// Connection draining in progress. Existing connections remain open until terminated
	BackendStatusDraining BackendStatus = "Draining"
)

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

type Loadbalancing struct {
	// LB algorithm configuration.
	//
	// +kubebuilder:validation:Required
	Algorithm LoadbalancingAlgorithm `json:"algorithm"`
}

// +kubebuilder:validation:XValidation:message="Exactly one algorithm (RoundRobin, LeastRequest or ConsistentHashing) must be specified",rule="(has(self.roundRobin) || has(self.leastRequest) || has(self.consistentHashing)) && !(has(self.roundRobin) && has(self.leastRequest)) && !(has(self.roundRobin) && has(self.consistentHashing)) && !(has(self.leastRequest) && has(self.consistentHashing))"
type LoadbalancingAlgorithm struct {
	// The round robin algorithm configuration. Exactly one of roundRobin, leastRequest or consistentHashing must be specified.
	//
	// +kubebuilder:validation:Optional
	RoundRobin *LoadbalancingAlgorithmRoundRobin `json:"roundRobin,omitempty"`

	// The least request algorithm configuration. Exactly one of roundRobin, leastRequest or consistentHashing must be specified.
	//
	// +kubebuilder:validation:Optional
	LeastRequest *LoadbalancingAlgorithmLeastRequest `json:"leastRequest,omitempty"`

	// The consistent hashing algorithm configuration. Exactly one of roundRobin, leastRequest or consistentHashing must be specified.
	//
	// +kubebuilder:validation:Optional
	ConsistentHashing *LoadbalancingAlgorithmConsistentHashing `json:"consistentHashing,omitempty"`
}

type LoadbalancingAlgorithmRoundRobin struct{}

type LoadbalancingAlgorithmLeastRequest struct{}

type LoadbalancingAlgorithmConsistentHashing struct {
	// Consistent hashing algorithm configuration.
	//
	// +kubebuilder:validation:Optional
	Algorithm *LoadbalancingConsistentHashingAlgorithm `json:"algorithm,omitempty"`
}

type LoadbalancingConsistentHashingAlgorithm struct {
	// The maglev configuration.
	//
	// +kubebuilder:validation:Required
	Maglev LoadbalancingConsistentHashingAlgorithmMaglev `json:"maglev"`
}

type LoadbalancingConsistentHashingAlgorithmMaglev struct {
	// The table size for Maglev hashing. Maglev aims for "minimal disruption" rather than an absolute guarantee.
	// Minimal disruption means that when the set of upstream hosts change, a connection will likely be sent to the same
	// upstream as it was before. Increasing the table size reduces the amount of disruption.
	// The table size must be prime number limited to 5000011. If it is not specified, the default is 65537.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=5000011
	TableSize *uint32 `json:"tableSize"`
}

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
