// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent,loadbalancer},singular="lbk8sbackendcluster",path="lbk8sbackendclusters",scope="Cluster",shortName={lbkbc}
// +kubebuilder:printcolumn:JSONPath=".metadata.name",name="Cluster Name",type=string
// +kubebuilder:printcolumn:JSONPath=".status.status",name="Status",type=string
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// LBK8sBackendCluster defines a remote Kubernetes cluster whose LoadBalancer
// services should be discovered and load balanced by the ILB control plane.
type LBK8sBackendCluster struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec LBK8sBackendClusterSpec `json:"spec"`

	// +optional
	Status *LBK8sBackendClusterStatus `json:"status,omitempty"`
}

type LBK8sBackendClusterSpec struct {
	// Authentication specifies how to authenticate to the remote cluster.
	//
	// +required
	Authentication LBK8sBackendClusterAuth `json:"authentication"`

	// TargetNamespace is the namespace where ILB resources (LBService, LBVIP,
	// LBBackendPool) will be created. If not specified, defaults to
	// "extlb-{clusterName}-{hashSuffix}" which is automatically created.
	//
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	TargetNamespace *string `json:"targetNamespace,omitempty"`

	// ServiceDiscovery contains one or more service discovery configurations.
	// These define how services in the remote cluster should be discovered and
	// health checked. If no ServiceDiscovery configurations are provided, the
	// controller will discover all LoadBalancer type services in the remote
	// cluster with default health check settings.
	//
	// +optional
	// +deepequal-gen=false
	ServiceDiscovery []LBK8sBackendClusterServiceDiscoveryConfig `json:"serviceDiscovery,omitempty"`
}

type LBK8sBackendClusterAuth struct {
	// SecretRef references a Secret containing authentication credentials.
	// The secret must contain a "kubeconfig" key with a valid kubeconfig file.
	//
	// +required
	SecretRef LBK8sBackendClusterSecretRef `json:"secretRef"`
}

type LBK8sBackendClusterSecretRef struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`

	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// LBK8sBackendClusterServiceDiscoveryConfig configures which services to discover
// and how they should be health checked.
type LBK8sBackendClusterServiceDiscoveryConfig struct {
	// Name identifies this discovery configuration. It is used in status
	// reporting to indicate which configuration discovered each service.
	//
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`

	// Namespaces limits service discovery to specific namespaces.
	// If empty, services from all namespaces will be discovered.
	//
	// +optional
	// +kubebuilder:validation:MaxItems=100
	// +listType=set
	Namespaces []string `json:"namespaces,omitempty"`

	// LabelSelector filters which services to discover based on labels. If not
	// specified, all LoadBalancer type services will be discovered.
	//
	// +optional
	// +deepequal-gen=false
	LabelSelector *metav1.LabelSelector `json:"labelSelector,omitempty"`

	// HealthCheck configures the health check settings for backends discovered
	// by this configuration. If not specified, defaults will be used.
	//
	// +optional
	HealthCheck *LBK8sBackendServiceHealthCheck `json:"healthCheck,omitempty"`
}

// LBK8sBackendServiceHealthCheck defines how a collection of discovered
// services should be health checked.
type LBK8sBackendServiceHealthCheck struct {
	// Protocol for health checks (currently only TCP).
	//
	// +optional
	// +kubebuilder:default=TCP
	Protocol *string `json:"protocol,omitempty"`

	// Ports to health check.
	// All ports must have a fully established connection for TCP
	//
	// +required
	// +listType=set
	Ports []*uint16 `json:"ports"`

	// IntervalSeconds is the interval between health check probes.
	//
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=30
	IntervalSeconds *int32 `json:"intervalSeconds,omitempty"`

	// TimeoutSeconds is the timeout for each health check probe.
	//
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=5
	TimeoutSeconds *int32 `json:"timeoutSeconds,omitempty"`
}

// +kubebuilder:validation:Enum=TCP
type LBExternalLBHealthCheckProtocol string

const (
	LBK8sBackendServiceHealthCheckProtocolTCP LBExternalLBHealthCheckProtocol = "TCP"
)

type LBK8sBackendClusterStatus struct {
	// Status is one of "OK" or "ConditionNotMet".
	// For detailed information, see the Message field of each condition.
	//
	// +optional
	Status *ExtLBResourceStatus `json:"status,omitempty"`

	// LastSyncTime is the timestamp of the last successful sync.
	//
	// +optional
	// +deepequal-gen=false
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// ServicesDiscovered is the number of services currently discovered
	// from this remote cluster.
	//
	// +optional
	ServicesDiscovered int32 `json:"servicesDiscovered,omitempty"`

	// DiscoveredServices lists the services that have been discovered and
	// their corresponding ILB resources.
	//
	// +optional
	// +listType=map
	// +listMapKey=namespace
	// +listMapKey=name
	// +deepequal-gen=false
	DiscoveredServices []LBK8sBackendClusterDiscoveredService `json:"discoveredServices,omitempty"`

	// Conditions represent the latest available observations of the
	// LBK8sBackendCluster's state.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

func (r *LBK8sBackendCluster) GetStatusCondition(conditionType string) *metav1.Condition {
	if r.Status == nil {
		return nil
	}
	for _, c := range r.Status.Conditions {
		if c.Type == conditionType {
			return &c
		}
	}
	return nil
}

func (r *LBK8sBackendCluster) UpsertStatusCondition(conditionType string, condition metav1.Condition) {
	if r.Status == nil {
		r.Status = &LBK8sBackendClusterStatus{}
	}
	conditionExists := false
	for i, c := range r.Status.Conditions {
		if c.Type == conditionType {
			if c.Status != condition.Status ||
				c.Reason != condition.Reason ||
				c.Message != condition.Message ||
				c.ObservedGeneration != condition.ObservedGeneration {
				r.Status.Conditions[i] = condition
			}
			conditionExists = true
			break
		}
	}

	if !conditionExists {
		r.Status.Conditions = append(r.Status.Conditions, condition)
	}
}

func (r *LBK8sBackendCluster) UpdateResourceStatus() {
	if r.Status == nil {
		r.Status = &LBK8sBackendClusterStatus{}
	}
	resourceStatus := ExtLBResourceStatusOK

	for _, c := range r.Status.Conditions {
		if c.Status == metav1.ConditionFalse {
			resourceStatus = ExtLBResourceStatusConditionNotMet
			break
		}
	}

	r.Status.Status = &resourceStatus
}

const (
	ConditionTypeClusterConnected = "lbk8sbackendcluster.isovalent.com/ClusterConnected"
	ConditionTypeSyncing          = "lbk8sbackendcluster.isovalent.com/Syncing"

	// DeprecatedConditionTypeClusterConnected is the old condition type from earlier
	// development. Cleaned up on reconcile.
	DeprecatedConditionTypeClusterConnected = "extlb.cilium.io/ClusterConnected"
)

const (
	ClusterConnectedReasonConnected           = "Connected"
	ClusterConnectedReasonConnectionFailed    = "ConnectionFailed"
	ClusterConnectedReasonAuthenticationError = "AuthenticationError"
	ClusterConnectedReasonConnectionError     = "ConnectionError"
	ClusterConnectedReasonSyncError           = "SyncError"

	SyncingReasonSyncing     = "Syncing"
	SyncingReasonPartialSync = "PartialSync"
)

// ExtLBResourceStatus represents the status of an external load balancer
// resource.  Note that unlike the use of LBResourceStatus, this status is used
// with a pointer type, so the initial value of "nil" means "Unknown"
// +kubebuilder:validation:Enum=OK;ConditionNotMet
type ExtLBResourceStatus string

const (
	ExtLBResourceStatusOK              ExtLBResourceStatus = "OK"
	ExtLBResourceStatusConditionNotMet ExtLBResourceStatus = "ConditionNotMet"
)

// LBK8sBackendClusterDiscoveredService represents a discovered service and
// its corresponding ILB resources.
type LBK8sBackendClusterDiscoveredService struct {
	// Status is the overall status of the discovered service.
	// For detailed information, refer to the Conditions on each of the referenced resources.
	//
	// +optional
	Status string `json:"status,omitempty"`

	// RemoteNamespace is the namespace of the source service in the remote cluster.
	//
	// +required
	RemoteNamespace string `json:"namespace"`

	// RemoteName is the name of the source service in the remote cluster.
	//
	// +required
	RemoteName string `json:"name"`

	// DiscoveryConfigName is the name of the ServiceDiscoveryConfig that
	// matched this service. Empty when the service was discovered by the
	// implicit catch-all configuration.
	//
	// +optional
	DiscoveryConfigName string `json:"discoveryConfigName,omitempty"`

	// LBServiceRefs are the references to the created LBService resources,
	// one per port on the remote service.
	//
	// +optional
	LBServiceRefs []LBExternalLBResourceRef `json:"lbServiceRefs,omitempty"`

	// LBVIPRefs are the references to the created LBVIP resources,
	// one per address family.
	//
	// +optional
	// +listType=atomic
	LBVIPRefs []LBExternalLBResourceRef `json:"lbVIPRefs,omitempty"`

	// LBBackendPoolRefs are the references to the created LBBackendPool
	// resources, one per port on the remote service.
	//
	// +optional
	LBBackendPoolRefs []LBExternalLBResourceRef `json:"lbBackendPoolRefs,omitempty"`

	// ExternalIPs are the allocated external IP addresses that were written
	// back to the source service, one per address family.
	//
	// +optional
	// +listType=atomic
	ExternalIPs []LBExternalIP `json:"externalIPs,omitempty"`

	// LastError contains the last error message if the service failed to sync.
	//
	// +optional
	LastError *string `json:"lastError,omitempty"`
}

// +kubebuilder:validation:Enum=Pending;Synced;Error
type LBK8sBackendClusterDiscoveredServiceStatus string

const (
	LBK8sBackendClusterDiscoveredServiceStatusPending LBK8sBackendClusterDiscoveredServiceStatus = "Pending"
	LBK8sBackendClusterDiscoveredServiceStatusSynced  LBK8sBackendClusterDiscoveredServiceStatus = "Synced"
	LBK8sBackendClusterDiscoveredServiceStatusError   LBK8sBackendClusterDiscoveredServiceStatus = "Error"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +deepequal-gen=false

type LBK8sBackendClusterList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []LBK8sBackendCluster `json:"items"`
}

type LBExternalLBResourceRef struct {
	// +required
	Namespace string `json:"namespace"`

	// +required
	Name string `json:"name"`
}

// LBExternalIP represents an allocated external IP address with its address
// family.
type LBExternalIP struct {
	// Family is the address family of the IP.
	//
	// +required
	// +kubebuilder:validation:Enum=ipv4;ipv6
	Family AddressFamily `json:"family"`

	// Address is the IP address.
	//
	// +required
	Address string `json:"address"`
}
