// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// IsovalentBGPPeerConfigList is a list of CiliumBGPPeer objects.
type IsovalentBGPPeerConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumBGPPeer.
	Items []IsovalentBGPPeerConfig `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalentbgp},singular="isovalentbgppeerconfig",path="isovalentbgppeerconfigs",scope="Cluster",shortName={ibgppeer}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

type IsovalentBGPPeerConfig struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the specification of the desired behavior of the IsovalentBGPPeerConfig.
	Spec IsovalentBGPPeerConfigSpec `json:"spec"`

	// Status is the running status of the IsovalentBGPPeerConfig
	//
	// +kubebuilder:validation:Optional
	Status IsovalentBGPPeerConfigStatus `json:"status"`
}

type IsovalentBGPPeerConfigSpec struct {
	// Transport defines the BGP transport parameters for the peer.
	//
	// If not specified, the default transport parameters are used.
	//
	// +kubebuilder:validation:Optional
	Transport *IsovalentBGPTransport `json:"transport,omitempty"`

	// Timers defines the BGP timers for the peer.
	//
	// If not specified, the default timers are used.
	//
	// +kubebuilder:validation:Optional
	Timers *v2alpha1.CiliumBGPTimers `json:"timers,omitempty"`

	// AuthSecretRef is the name of the secret to use to fetch a TCP
	// authentication password for this peer.
	//
	// If not specified, no authentication is used.
	//
	// +kubebuilder:validation:Optional
	AuthSecretRef *string `json:"authSecretRef,omitempty"`

	// GracefulRestart defines graceful restart parameters which are negotiated
	// with this peer.
	//
	// If not specified, the graceful restart capability is disabled.
	//
	// +kubebuilder:validation:Optional
	GracefulRestart *v2alpha1.CiliumBGPNeighborGracefulRestart `json:"gracefulRestart,omitempty"`

	// EBGPMultihopTTL controls the multi-hop feature for eBGP peers.
	// Its value defines the Time To Live (TTL) value used in BGP
	// packets sent to the peer.
	//
	// If not specified, EBGP multihop is disabled. This field is ignored for iBGP neighbors.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=255
	// +kubebuilder:default=1
	EBGPMultihop *int32 `json:"ebgpMultihop,omitempty"`

	// Families, if provided, defines a set of AFI/SAFIs the speaker will
	// negotiate with it's peer.
	//
	// If not specified, the default families of IPv6/unicast and IPv4/unicast will be created.
	//
	// +kubebuilder:validation:Optional
	Families []v2alpha1.CiliumBGPFamilyWithAdverts `json:"families,omitempty"`

	// BFDProfileRef is the name of the BFD profile used to establish a BFD (Bidirectional Forwarding Detection)
	// session with the peer. If not set, BFD is not used for this peer.
	//
	// +kubebuilder:validation:Optional
	BFDProfileRef *string `json:"bfdProfileRef,omitempty"`
}

// IsovalentBGPTransport defines the BGP transport parameters for the peer.
type IsovalentBGPTransport struct {
	// PeerPort is the peer port to be used for the BGP session.
	//
	// If not specified, defaults to TCP port 179.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=179
	PeerPort *int32 `json:"peerPort,omitempty"`
}

type IsovalentBGPPeerConfigStatus struct {
	// The current conditions of the CiliumBGPPeerConfig
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Conditions for IsovalentBGPPeerConfig
const (
	// Referenced auth secret is missing
	BGPPeerConfigConditionMissingAuthSecret = "isovalent.com/MissingAuthSecret"
	// Referenced BFDProfile is missing
	BGPPeerConfigConditionMissingBFDProfile = "isovalent.com/MissingBFDProfile"
)

var AllBGPPeerConfigConditions = []string{
	BGPPeerConfigConditionMissingAuthSecret,
	BGPPeerConfigConditionMissingBFDProfile,
}

func (t *IsovalentBGPTransport) SetDefaults() {
	if t.PeerPort == nil || *t.PeerPort == 0 {
		t.PeerPort = ptr.To[int32](v2alpha1.DefaultBGPPeerPort)
	}
}

func (p *IsovalentBGPPeerConfigSpec) SetDefaults() {
	if p == nil {
		return
	}

	if p.Transport == nil {
		p.Transport = &IsovalentBGPTransport{}
	}
	p.Transport.SetDefaults()

	if p.Timers == nil {
		p.Timers = &v2alpha1.CiliumBGPTimers{}
	}
	p.Timers.SetDefaults()

	if p.EBGPMultihop == nil {
		p.EBGPMultihop = ptr.To[int32](v2alpha1.DefaultBGPEBGPMultihopTTL)
	}

	if p.GracefulRestart == nil {
		p.GracefulRestart = &v2alpha1.CiliumBGPNeighborGracefulRestart{}
	}
	p.GracefulRestart.SetDefaults()

	if len(p.Families) == 0 {
		p.Families = []v2alpha1.CiliumBGPFamilyWithAdverts{
			{
				CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
					Afi:  "ipv6",
					Safi: "unicast",
				},
			},
			{
				CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
					Afi:  "ipv4",
					Safi: "unicast",
				},
			},
		}
	}
}
