// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package addressing

import (
	"cmp"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"

	daemonK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/api/v1/models"
	"github.com/cilium/cilium/enterprise/api/v1/server/restapi/network"
	"github.com/cilium/cilium/enterprise/pkg/api"
	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var Cell = cell.Group(
	cell.ProvidePrivate(newPrivNetAPI),
	cell.Provide(newPrivNetAPIHandler),
)

// vNICIndex represents the index of a vNIC. The zero index represents the primary
// interface, and subsequent ones correspond to secondary interfaces, computed based
// on the position of the corresponding entry in the Multus network attachment annotation.
type vNICIndex uint

// Primary returns whether the index corresponds to the primary interface.
func (idx vNICIndex) Primary() bool { return idx == 0 }

type apiParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	Log       *slog.Logger

	DB                   *statedb.DB
	PrivateNetworkConfig config.Config
	DaemonConfig         *option.DaemonConfig
	Pods                 statedb.Table[daemonK8s.LocalPod]
	PrivateNetworks      statedb.Table[tables.PrivateNetwork]
	Subnets              statedb.Table[tables.Subnet]
}

type cfg struct {
	privateNetworkConfig config.Config

	enableIPv4 bool
	enableIPv6 bool
}

type PrivNetAPI struct {
	db  *statedb.DB
	cfg cfg
	log *slog.Logger

	pods            statedb.Table[daemonK8s.LocalPod]
	privateNetworks statedb.Table[tables.PrivateNetwork]
	subnets         statedb.Table[tables.Subnet]
}

func newPrivNetAPI(p apiParams) *PrivNetAPI {
	return &PrivNetAPI{
		db: p.DB,
		cfg: cfg{
			privateNetworkConfig: p.PrivateNetworkConfig,

			enableIPv4: p.DaemonConfig.EnableIPv4,
			enableIPv6: p.DaemonConfig.EnableIPv6,
		},
		log:             p.Log,
		pods:            p.Pods,
		privateNetworks: p.PrivateNetworks,
		subnets:         p.Subnets,
	}
}

func (n *PrivNetAPI) GetPrivateNetworkAddressing(p network.GetNetworkPrivateAddressingParams) (*models.PrivateNetworkAddressing, error) {
	if (p.Network == nil) != (p.Subnet == nil) {
		return nil, fmt.Errorf("both network and subnet must be set in CNI configuration if one is provided")
	}

	if !n.cfg.privateNetworkConfig.Enabled {
		if p.Network != nil {
			return nil, fmt.Errorf("target network set in CNI configuration, but private networks is disabled")
		}

		// Don't look at network attachment annotations if privnet is disabled, attach to
		// default network.
		return nil, nil
	}

	podNamespaceName := fmt.Sprintf("%s/%s", p.PodNamespace, p.PodName)

	txn := n.db.ReadTxn()
	pod, _, found := n.pods.Get(txn, daemonK8s.PodByName(p.PodNamespace, p.PodName))
	if !found {
		return nil, fmt.Errorf("pod %s not found", podNamespaceName)
	} else if string(pod.UID) != p.PodUID {
		return nil, fmt.Errorf("pod %s UID does not match pod object in store (got %q, want %q)",
			podNamespaceName, pod.UID, p.PodUID)
	}

	attachments, err := types.ExtractNetworkAttachmentAnnotation(pod)
	if err != nil {
		return nil, err
	} else if len(attachments) == 0 {
		if p.Network != nil {
			return nil, fmt.Errorf("target network set in CNI configuration, but %q annotation is missing on pod %s",
				types.PrivateNetworkAnnotation, podNamespaceName,
			)
		}

		// Annotation not found, attach to default network.
		return nil, nil
	}

	var attachment = attachments[0]

	if p.Network != nil && *p.Network != attachment.Network {
		return nil, fmt.Errorf("mismatching target network in CNI configuration (%q) and %q annotation on pod %s (%q)",
			*p.Network, types.PrivateNetworkAnnotation, podNamespaceName, attachment.Network,
		)
	}

	privnet, _, found := n.privateNetworks.Get(txn, tables.PrivateNetworkByName(tables.NetworkName(attachment.Network)))
	if !found {
		return nil, fmt.Errorf("invalid network %q in %q annotation on pod %s",
			attachment.Network, types.PrivateNetworkAnnotation, podNamespaceName)
	}

	inactive, err := types.ExtractInactiveAnnotation(pod)
	if err != nil {
		return nil, fmt.Errorf("invalid value in %q annotation on pod %s/%s: %w",
			types.PrivateNetworkInactiveAnnotation, pod.Namespace, pod.Name, err)
	}

	activatedAt := time.Now().UTC()
	if inactive {
		activatedAt = time.Time{} // zero value means inactive
	}

	addressing := &models.PrivateNetworkAddressing{
		Address:     &models.AddressPair{},
		Mac:         attachment.MAC.String(),
		Network:     attachment.Network,
		ActivatedAt: strfmt.DateTime(activatedAt),
	}

	var ipv4, ipv6 netip.Addr

	if n.cfg.enableIPv4 {
		if !attachment.IPv4.Is4() {
			return nil, fmt.Errorf("invalid IPv4 address %q in %q annotation on pod %s",
				attachment.IPv4, types.PrivateNetworkAnnotation, podNamespaceName)
		}
		addressing.Address.IPV4 = attachment.IPv4.String()
		ipv4 = attachment.IPv4
	}

	if n.cfg.enableIPv6 {
		if !attachment.IPv6.Is6() {
			return nil, fmt.Errorf("invalid IPv6 address %q in %q annotation on pod %s",
				attachment.IPv6, types.PrivateNetworkAnnotation, podNamespaceName)
		}
		addressing.Address.IPV6 = attachment.IPv6.String()
		ipv6 = attachment.IPv6
	}

	subnet, err := n.subnetForIPs(txn, privnet.Name, (*tables.SubnetName)(p.Subnet), ipv4, ipv6)
	if err != nil {
		return nil, err
	}

	addressing.Routes = n.routes(0, subnet)
	return addressing, nil
}

func (n *PrivNetAPI) subnetForIPs(txn statedb.ReadTxn, privnet tables.NetworkName, sname *tables.SubnetName, ipv4, ipv6 netip.Addr) (tables.Subnet, error) {
	var subnet tables.Subnet
	var subnetv4, subnetv6 tables.SubnetName

	if ipv4.IsValid() {
		if sub, ok := tables.FindSubnetForIPs(n.subnets, txn, privnet, ipv4); ok {
			subnet = sub
			subnetv4 = sub.Name
		}
	}
	if ipv6.IsValid() {
		if sub, ok := tables.FindSubnetForIPs(n.subnets, txn, privnet, ipv6); ok {
			subnet = sub
			subnetv6 = sub.Name
		}
	}

	switch {
	case ipv4.IsValid() && subnetv4 == "":
		return tables.Subnet{}, fmt.Errorf("requested IP %s not in range of defined subnets", ipv4)
	case ipv6.IsValid() && subnetv6 == "":
		return tables.Subnet{}, fmt.Errorf("requested IP %s not in range of defined subnets", ipv6)
	case ipv4.IsValid() && ipv6.IsValid() && subnetv4 != subnetv6:
		return tables.Subnet{}, fmt.Errorf("requested IP %s not in range of the subnet of the IP %s", ipv6, ipv4)
	case sname != nil && *sname != cmp.Or(subnetv4, subnetv6):
		return tables.Subnet{}, fmt.Errorf("requested IPs are not in range of the requested subnet (%q)", *sname)
	default:
		return subnet, nil
	}
}

// routes returns the list of routes to be configured for a private networks enabled endpoint.
// Specifically, for each IP family that is enabled, we configure the following routes.
//
// * For the primary interface:
//   - A route towards a link local address -- $link_local_address via $iface
//   - A default route -- default via $link_local_address
//
// * For secondary interfaces:
//   - A route towards a link local address, similarly as for the primary one.
//     The link local address is generated based on vNIC index.
//   - A route for the subnet CIDR -- $subnet_cidr via $link_local_address.
//     This mimics the route that would be automatically created if we propagated
//     the actual subnet mask, rather than leveraging /32 and /128 addresses.
//
// We leverage a link local address as nexthop, rather than simply setting the default route
// via the egress interface, to avoid the need for a neighbor lookup for every destination IP.
func (n *PrivNetAPI) routes(idx vNICIndex, subnet tables.Subnet) (out []*models.NetworkAttachmentRoute) {
	var pfx = func(def string, subnet netip.Prefix) string {
		if idx.Primary() {
			return def
		}

		return subnet.String()
	}

	if n.cfg.enableIPv4 && subnet.CIDRv4.IsValid() {
		var gw = fmt.Sprintf("169.254.0.%d", idx+1)

		out = append(out,
			&models.NetworkAttachmentRoute{Destination: gw + "/32"},
			&models.NetworkAttachmentRoute{Destination: pfx("0.0.0.0/0", subnet.CIDRv4), Gateway: gw},
		)
	}

	if n.cfg.enableIPv6 && subnet.CIDRv6.IsValid() {
		var gw = fmt.Sprintf("fe80::%x", idx+1)

		out = append(out,
			&models.NetworkAttachmentRoute{Destination: gw + "/128"},
			&models.NetworkAttachmentRoute{Destination: pfx("::/0", subnet.CIDRv6), Gateway: gw},
		)
	}

	return out
}

// newPrivNetAPIHandler returns a default handler for the /network/private/addressing API endpoint
func newPrivNetAPIHandler(n *PrivNetAPI) network.GetNetworkPrivateAddressingHandler {
	return api.NewHandler(func(p network.GetNetworkPrivateAddressingParams) middleware.Responder {
		addressing, err := n.GetPrivateNetworkAddressing(p)
		if err != nil {
			return network.NewGetNetworkPrivateAddressingFailure().WithPayload(models.Error(err.Error()))
		}

		return network.NewGetNetworkPrivateAddressingOK().WithPayload(&models.PrivateNetworkAddressingResponse{
			Addressing: addressing,
		})
	})
}
