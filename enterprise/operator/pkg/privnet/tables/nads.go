// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tables

import (
	"cmp"
	"strconv"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
)

// NamespacedName represents a namespace and name pair.
type NamespacedName types.NamespacedName

func (nn NamespacedName) String() string { return types.NamespacedName(nn).String() }
func (nn NamespacedName) Key() index.Key { return index.String(nn.String()) }

// NetworkAttachmentDefinition represents a Multus NetworkAttachmentDefinition
// instance observed from Kubernetes.
type NetworkAttachmentDefinition struct {
	// NamespacedName identifies the namespace and name of the NAD.
	NamespacedName

	// Labels is the set of labels associated with the NAD.
	Labels labels.Set

	// Annotations is the set of annotations associated with the NAD.
	Annotations map[string]string

	// Managed specifies whether the NAD is owned by us, or managed externally.
	Managed bool

	// UID is the unique identifier of the NAD.
	UID types.UID

	// ResourceVersion is the opaque value representing the NAD version.
	ResourceVersion string

	// CNIConfig is the CNI configuration associated with the NAD.
	CNIConfig NADCNIConfig
}

// NADCNIConfig represents the fields of interest of the CNI configuration.
type NADCNIConfig struct {
	NADCNIConfigCore `json:",inline" yaml:",inline"`

	EnableDebug bool   `json:"enable-debug" yaml:"enable-debug"`
	LogFormat   string `json:"log-format,omitempty" yaml:"log-format,omitempty"`
	LogFile     string `json:"log-file,omitempty" yaml:"log-file,omitempty"`

	PrivateNetworks NADCNIConfigPrivateNetworks `json:"private-networks" yaml:"private-networks"`
}

// NADCNIConfigCore represents the core fields of the CNI configuration.
type NADCNIConfigCore struct {
	CNIVersion string `json:"cniVersion" yaml:"cniVersion"`
	Type       string `json:"type" yaml:"type"`
}

// NADCNIConfigPrivateNetworks represents the private networks specific fields
// of the CNI configuration.
type NADCNIConfigPrivateNetworks struct {
	Network string `json:"network,omitempty" yaml:"network,omitempty"`
	Subnet  string `json:"subnet,omitempty" yaml:"subnet,omitempty"`
}

// NADCNIConfigTypeCilium is the CNI config type referencing the Cilium CNI plugin.
const NADCNIConfigTypeCilium = "cilium-cni"

// Network returns the network name associated with the given NAD, inferred
// from the corresponding CNI configuration field.
func (nad NetworkAttachmentDefinition) Network() NetworkName {
	return NetworkName(nad.CNIConfig.PrivateNetworks.Network)
}

// Subnet returns the subnet name associated with the given NAD, inferred
// from the corresponding CNI configuration field.
func (nad NetworkAttachmentDefinition) Subnet() SubnetName {
	return SubnetName(nad.CNIConfig.PrivateNetworks.Subnet)
}

var _ statedb.TableWritable = NetworkAttachmentDefinition{}

func (nad NetworkAttachmentDefinition) TableHeader() []string {
	return []string{"Namespace", "Name", "Type", "Network", "Subnet", "Managed"}
}

func (nad NetworkAttachmentDefinition) TableRow() []string {
	var fallback = "N/A"
	if nad.CNIConfig.Type == NADCNIConfigTypeCilium {
		fallback = "__unknown__"
	}

	return []string{
		nad.Namespace,
		nad.Name,
		cmp.Or(string(nad.CNIConfig.Type), "__unknown__"),
		cmp.Or(string(nad.Network()), fallback),
		cmp.Or(string(nad.Subnet()), fallback),
		strconv.FormatBool(nad.Managed),
	}
}

const (
	// indexDelimiter is the delimiter used to concatenate strings for composite indexes.
	indexDelimiter = "|"
)

// nadKey is <network-name>|<subnet-name>|<namespace-name>
type nadKey string

func (key nadKey) Key() index.Key {
	return index.String(string(key))
}

func newNADKeyFromNetwork(network NetworkName) nadKey {
	return nadKey(string(network) + indexDelimiter)
}

func newNADKeyFromNetworkAndSubnet(network NetworkName, subnet SubnetName) nadKey {
	return newNADKeyFromNetwork(network) + nadKey(subnet) + indexDelimiter
}

func newNADKey(network NetworkName, subnet SubnetName, namespace string) nadKey {
	return newNADKeyFromNetworkAndSubnet(network, subnet) + nadKey(namespace)
}

var (
	nadsNamespacedNameIndex = statedb.Index[NetworkAttachmentDefinition, NamespacedName]{
		Name: "namespaced-name",
		FromObject: func(obj NetworkAttachmentDefinition) index.KeySet {
			return index.NewKeySet(obj.NamespacedName.Key())
		},
		FromKey:    NamespacedName.Key,
		FromString: index.FromString,
		Unique:     true,
	}

	nadsNetworkSubnetNamespaceIndex = statedb.Index[NetworkAttachmentDefinition, nadKey]{
		Name: "network-subnet-namespace",
		FromObject: func(obj NetworkAttachmentDefinition) index.KeySet {
			if network, subnet := obj.Network(), obj.Subnet(); network != "" && subnet != "" {
				return index.NewKeySet(newNADKey(network, subnet, obj.Namespace).Key())
			}

			return index.NewKeySet()
		},
		FromKey:    nadKey.Key,
		FromString: index.FromString,
		Unique:     false,
	}

	// NADByNamespacedName queries the NetworkAttachmentDefinitions table by namespaced name.
	NADByNamespacedName = nadsNamespacedNameIndex.Query
)

// NADsByNetworkSubnetAndNamespace queries the NetworkAttachmentDefinitions table by network, subnet and namespace name.
func NADsByNetworkSubnetAndNamespace(network tables.NetworkName, subnet tables.SubnetName, namespace string,
) statedb.Query[NetworkAttachmentDefinition] {
	return nadsNetworkSubnetNamespaceIndex.Query(newNADKey(network, subnet, namespace))
}

func NewNetworkAttachmentDefinitionsTable(db *statedb.DB) (statedb.RWTable[NetworkAttachmentDefinition], error) {
	return statedb.NewTable(
		db,
		"privnet-nads",
		nadsNamespacedNameIndex,
		nadsNetworkSubnetNamespaceIndex,
	)
}
