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
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	multusv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	multusutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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

	attachment, nicidx, err := n.getAttachmentFor(pod, p.Ifname)
	if err != nil {
		return nil, err
	} else if attachment == nil {
		if p.Network != nil {
			return nil, fmt.Errorf("target network set in CNI configuration, but %q annotation is missing on pod %s",
				types.PrivateNetworkAnnotation, podNamespaceName,
			)
		}

		// Annotation not found, attach to default network.
		return nil, nil
	}

	var annotation = types.PrivateNetworkAnnotation
	if !nicidx.Primary() {
		annotation = types.PrivateNetworkSecondaryAttachmentsAnnotation
	}

	if p.Network != nil && *p.Network != attachment.Network {
		return nil, fmt.Errorf("mismatching target network in CNI configuration (%q) and %q annotation on pod %s (%q)",
			*p.Network, annotation, podNamespaceName, attachment.Network,
		)
	}

	privnet, _, found := n.privateNetworks.Get(txn, tables.PrivateNetworkByName(tables.NetworkName(attachment.Network)))
	if !found {
		return nil, fmt.Errorf("invalid network %q in %q annotation on pod %s",
			attachment.Network, annotation, podNamespaceName)
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
				attachment.IPv4, annotation, podNamespaceName)
		}
		addressing.Address.IPV4 = attachment.IPv4.String()
		ipv4 = attachment.IPv4
	}

	if n.cfg.enableIPv6 {
		if !attachment.IPv6.Is6() {
			return nil, fmt.Errorf("invalid IPv6 address %q in %q annotation on pod %s",
				attachment.IPv6, annotation, podNamespaceName)
		}
		addressing.Address.IPV6 = attachment.IPv6.String()
		ipv6 = attachment.IPv6
	}

	subnet, err := n.subnetForIPs(txn, privnet.Name, (*tables.SubnetName)(p.Subnet), ipv4, ipv6)
	if err != nil {
		return nil, err
	}

	addressing.Routes = n.routes(nicidx, subnet)
	return addressing, nil
}

// getAttachmentFor returns the network attachment associated with the given interface of a pod, and
// the corresponding vNIC index, computed based on the position of the entry in the Multus network
// attachment annotation.
func (n *PrivNetAPI) getAttachmentFor(pod metav1.Object, ifname string) (*types.NetworkAttachment, vNICIndex, error) {
	attachments, err := types.ExtractNetworkAttachmentAnnotation(pod)
	if err != nil || len(attachments) == 0 {
		return nil, 0, err
	}

	// The attachment for the primary interface is always the first one.
	const primary = "eth0"
	if ifname == primary {
		return &attachments[0], 0, nil
	}

	attachments = attachments[1:]

	// Lookup the entry matching the given interface name inside the "k8s.v1.cni.cncf.io/networks" annotation.
	elems, err := multusutils.ParsePodNetworkAnnotation(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: pod.GetName(), Namespace: pod.GetNamespace(), Annotations: pod.GetAnnotations(),
	}})
	if err != nil {
		return nil, 0, fmt.Errorf("unable to parse %q annotation: %w", multusv1.NetworkAttachmentAnnot, err)
	}

	nicidx, duplicate := -1, false
	for i, elem := range elems {
		// If no interface name is specified, Multus constructs it based on the position of the delegate.
		// https://github.com/k8snetworkplumbingwg/multus-cni/blob/39d6a8ffd2fb/pkg/multus/multus.go#L92-L105
		if ifname == cmp.Or(elem.InterfaceRequest, fmt.Sprintf("net%d", i+1)) {
			duplicate, nicidx = nicidx != -1, i
		}
	}

	switch {
	case duplicate:
		return nil, 0, fmt.Errorf("duplicate entry found for interface %q in %q annotation", ifname, multusv1.NetworkAttachmentAnnot)
	case nicidx == -1:
		return nil, 0, fmt.Errorf("no entry found for interface %q in %q annotation", ifname, multusv1.NetworkAttachmentAnnot)
	}

	// If the attachments specify the interface name, we can rely on it to retrieve the matching one.
	var naidx = nicidx
	if len(attachments) > 0 && attachments[0].Interface != "" {
		// Copied from the Kubevirt implementation of [GenerateHashedInterfaceName], to avoid introducing a dependency.
		// https://github.com/kubevirt/kubevirt/blob/1ac3f5208a1f/pkg/network/namescheme/networknamescheme.go#L80-L85
		var kubevirtHashedInterfaceName = func(networkName string) string {
			hash := sha256.New()
			_, _ = io.WriteString(hash, networkName)
			hashedName := fmt.Sprintf("%x", hash.Sum(nil))[:11]
			return fmt.Sprintf("%s%s", "pod", hashedName)
		}

		naidx = -1
		for i, na := range attachments {
			if ifname == na.Interface || ifname == kubevirtHashedInterfaceName(na.Interface) {
				duplicate, naidx = naidx != -1, i
			}
		}
	}

	switch {
	case duplicate:
		return nil, 0, fmt.Errorf("duplicate network attachment found for interface %q in %q annotation",
			ifname, types.PrivateNetworkSecondaryAttachmentsAnnotation)
	case naidx == -1 || naidx >= len(attachments):
		return nil, 0, fmt.Errorf("no network attachment found for interface %q in %q annotation",
			ifname, types.PrivateNetworkSecondaryAttachmentsAnnotation)
	case naidx >= 64:
		return nil, 0, fmt.Errorf("at most 64 secondary interfaces are supported")
	default:
		// We return the index in the Multus annotation, rather than the one of the
		// attachment entry, so that it is future proof once we make attachments optional.
		return &attachments[naidx], vNICIndex(nicidx + 1), nil
	}
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
