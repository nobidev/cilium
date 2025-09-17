// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalentbgp},singular="isovalentbgpnodeconfigoverride",path="isovalentbgpnodeconfigoverrides",scope="Cluster",shortName={ibgpnodeoverride}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

// IsovalentBGPNodeConfigOverride specifies configuration overrides for a IsovalentBGPNodeConfig.
// It allows fine-tuning of BGP behavior on a per-node basis. For the override to be effective,
// the names in IsovalentBGPNodeConfigOverride and IsovalentBGPNodeConfig must match exactly. This
// matching ensures that specific node configurations are applied correctly and only where intended.
type IsovalentBGPNodeConfigOverride struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the specification of the desired behavior of the IsovalentBGPNodeConfigOverride.
	Spec IsovalentBGPNodeConfigOverrideSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// IsovalentBGPNodeConfigOverrideList is a list of IsovalentBGPNodeConfigOverride objects.
type IsovalentBGPNodeConfigOverrideList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of IsovalentBGPNodeConfigOverride.
	Items []IsovalentBGPNodeConfigOverride `json:"items"`
}

type IsovalentBGPNodeConfigOverrideSpec struct {
	// BGPInstances is a list of BGP instances to override.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +listType=map
	// +listMapKey=name
	BGPInstances []IsovalentBGPNodeConfigInstanceOverride `json:"bgpInstances"`
}

type IsovalentBGPNodeConfigInstanceOverride struct {
	// Name is the name of the BGP instance for which the configuration is overridden.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// RouterID is BGP router id to use for this instance. It must be unique across all BGP instances.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=ipv4
	RouterID *string `json:"routerID,omitempty"`

	// LocalPort is port to use for this BGP instance.
	//
	// +kubebuilder:validation:Optional
	LocalPort *int32 `json:"localPort,omitempty"`

	// SRv6 Responder is a flag to enable SRv6 responder functionality on this BGP instance.
	//
	// +kubebuilder:validation:Optional
	SRv6Responder *bool `json:"srv6Responder,omitempty"`

	// LocalASN is the ASN to use for this BGP instance.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	LocalASN *int64 `json:"localASN,omitempty"`

	// Peers is a list of peer configurations to override.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=name
	Peers []IsovalentBGPNodeConfigPeerOverride `json:"peers,omitempty"`

	// Maintenance allows overriding maintenance mode of this BGP instance on the node.
	// If configured, it overrides the node's maintenance mode that would be otherwise set
	// automatically when the node is cordoned / uncordoned (if that feature is enabled).
	//
	// +kubebuilder:validation:Optional
	Maintenance *IsovalentBGPMaintenance `json:"maintenance"`
}

// IsovalentBGPNodeConfigPeerOverride defines configuration options which can be overridden for a specific peer.
type IsovalentBGPNodeConfigPeerOverride struct {
	// Name is the name of the peer for which the configuration is overridden.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// LocalAddress is the IP address to use for connecting to this peer.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern=`((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))`
	LocalAddress *string `json:"localAddress,omitempty"`

	// AutoDiscovery allows auto-discovery of peer's IP address.
	//
	// +kubebuilder:validation:Optional
	AutoDiscovery *BGPAutoDiscovery `json:"autoDiscovery,omitempty"`

	// LocalPort is source port to use for connecting to this peer.
	//
	// +kubebuilder:validation:Optional
	LocalPort *int32 `json:"localPort,omitempty"`
}

// BGPMaintenanceMode defines the maintenance mode of a BGP instance on the node.
//
// +kubebuilder:validation:Enum=Disabled;Community;Withdrawal
type BGPMaintenanceMode string

const (
	// BGPMaintenanceModeDisabled disables maintenance mode of a BGP instance on the node.
	BGPMaintenanceModeDisabled BGPMaintenanceMode = "Disabled"

	// BGPMaintenanceModeCommunity enables sending of the GRACEFUL_SHUTDOWN BGP community
	// with the k8s service routes advertised to the peers.
	BGPMaintenanceModeCommunity BGPMaintenanceMode = "Community"

	// BGPMaintenanceModeWithdrawal enforces withdrawal of k8s service routes advertised to the peers.
	BGPMaintenanceModeWithdrawal BGPMaintenanceMode = "Withdrawal"
)

// IsovalentBGPMaintenance allows configuring maintenance mode of a BGP instance on the node.
type IsovalentBGPMaintenance struct {
	// Mode defines the maintenance mode of a BGP instance on the node:
	// - "Community" enables sending of the GRACEFUL_SHUTDOWN BGP community in the k8s service advertisements.
	// - "Withdrawal" enforces withdrawal of k8s service advertisements.
	// - "Disabled" explicitly disables maintenance mode of a BGP instance on the node.
	//
	// +kubebuilder:validation:Required
	Mode BGPMaintenanceMode `json:"mode"`
}
