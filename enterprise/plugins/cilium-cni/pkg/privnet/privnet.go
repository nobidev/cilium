// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package privnet

import (
	"fmt"
	"net"
	"net/netip"

	cniTypesV1 "github.com/containernetworking/cni/pkg/types/100"

	"github.com/cilium/cilium/api/v1/models"
	enterpriseModels "github.com/cilium/cilium/enterprise/api/v1/models"
	"github.com/cilium/cilium/enterprise/pkg/client"
	"github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	privnetTypes "github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/plugins/cilium-cni/cmd"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
)

type addHooks struct {
	// Set in OnConfigReady
	ceeClient      *client.EnterpriseClient
	privNetEnabled bool
	cniArgs        *types.ArgsSpec
	daemonConf     *models.DaemonConfigurationStatus

	// Set in OnIPAMReady
	ipam *models.IPAMResponse

	// Set in OnLinkConfigReady
	privNetAddressing *enterpriseModels.PrivateNetworkAddressing
}

func NewAddHooks() *addHooks {
	return &addHooks{}
}

func (h *addHooks) OnConfigReady(netConf *types.NetConf, cniArgs *types.ArgsSpec, conf *models.DaemonConfigurationStatus) error {
	ceeClient, err := client.NewDefaultClient()
	if err != nil {
		return fmt.Errorf("unable to create enterprise API client: %w", err)
	}

	config, err := ceeClient.EnterpriseConfig()
	if err != nil {
		return fmt.Errorf("unable to get enterprise configuration: %w", err)
	}

	// Store for later callbacks
	h.ceeClient = ceeClient
	h.privNetEnabled = config.PrivateNetworks != nil && config.PrivateNetworks.Enabled
	h.cniArgs = cniArgs
	h.daemonConf = conf

	return nil
}

func (h *addHooks) OnIPAMReady(ipam *models.IPAMResponse) error {
	// Store for later callbacks
	h.ipam = ipam

	return nil
}

func (h *addHooks) OnLinkConfigReady(linkConfig *connector.LinkConfig) error {
	// privnet not enabled, don't modify
	if !h.privNetEnabled || h.cniArgs == nil || h.daemonConf == nil {
		return nil
	}

	privNetAddressing, err := h.ceeClient.PrivateNetworkAddressing(
		string(h.cniArgs.K8S_POD_NAMESPACE),
		string(h.cniArgs.K8S_POD_NAME),
		string(h.cniArgs.K8S_POD_UID),
	)
	if err != nil {
		return fmt.Errorf("unable to determine private network: %w", err)
	}

	// Store for later callbacks
	h.privNetAddressing = privNetAddressing.Addressing

	// Modify passed LinkConfig
	if h.privNetAddressing != nil && h.privNetAddressing.Network != "" {
		// MTU for privnet enabled pods should be set on pod/lxc devices instead of default route
		// inside the pod. As address configured is not necessarily /32 or /128, so traffic will
		// exit without using default route where MTU is typically set.
		linkConfig.DeviceMTU = int(h.daemonConf.RouteMTU)
	}

	return nil
}

var (
	// defaultV4Route is the default IPv4 route 0.0.0.0/0
	defaultV4Route = net.IPNet{
		IP:   net.IPv4zero,
		Mask: net.CIDRMask(0, 8*net.IPv4len),
	}
	// defaultV6Route is the default IPv6 route ::/0
	defaultV6Route = net.IPNet{
		IP:   net.IPv6zero,
		Mask: net.CIDRMask(0, 8*net.IPv6len),
	}

	linkLocalV4Prefix = net.ParseIP("169.254.0.1")
	linkLocalV6Prefix = net.ParseIP("fe80::1")
)

func (h *addHooks) OnInterfaceConfigReady(state *cmd.CmdState, ep *models.EndpointChangeRequest, res *cniTypesV1.Result) error {
	// privnet not enabled or not a privnet-attached endpoint, don't modify
	if !h.privNetEnabled || h.privNetAddressing == nil || h.privNetAddressing.Network == "" || h.ipam == nil {
		return nil
	}

	// Remove the `default via cilium_host` route installed by prepareIPs before the callback.
	// After this, `state` should only contain IPs and routes in the inner network,
	*state = cmd.CmdState{}
	res.Routes = nil

	ipv4Enabled := cmd.IPv4IsEnabled(h.ipam)
	ipv6Enabled := cmd.IPv6IsEnabled(h.ipam)

	routeMTU := int(h.daemonConf.RouteMTU)
	if ipv4Enabled {
		// add default route with link local nexthop
		state.IP4routes = append(state.IP4routes, route.Route{
			Prefix:  defaultV4Route,
			Nexthop: &linkLocalV4Prefix,
			MTU:     routeMTU,
		})

		// add link-local route
		state.IP4routes = append(state.IP4routes, route.Route{
			Prefix: *iputil.IPToPrefix(linkLocalV4Prefix),
			MTU:    routeMTU,
		})

	}

	if ipv6Enabled {
		// add default route with link local nexthop
		state.IP6routes = append(state.IP6routes, route.Route{
			Prefix:  defaultV6Route,
			Nexthop: &linkLocalV6Prefix,
			MTU:     routeMTU,
		})

		// add link-local route
		state.IP6routes = append(state.IP6routes, route.Route{
			Prefix: *iputil.IPToPrefix(linkLocalV6Prefix),
			MTU:    routeMTU,
		})
	}

	if ep.Properties == nil {
		ep.Properties = map[string]any{}
	}
	ep.Properties[endpoints.PropertyPrivNetNetwork] = h.privNetAddressing.Network

	// TODO: Should we allow this kind of label to be set via API or should it be treated like `reserved` labels
	// and be set by the daemon on endpoint creation?
	lbl := labels.NewLabel(privnetTypes.CNINetworkNameLabel, h.privNetAddressing.Network, labels.LabelSourceCNI)
	ep.Labels = append(ep.Labels, lbl.String())

	if ipv4Enabled && h.daemonConf.Addressing.IPV4 != nil {
		netIPv4, err := netip.ParseAddr(h.privNetAddressing.Address.IPV4)
		if err != nil {
			return fmt.Errorf("unable to parse private network IPv4 address: %w", err)
		}
		state.IP4 = netIPv4

		ep.Properties[endpoints.PropertyPrivNetIPv4] = h.privNetAddressing.Address.IPV4
	}

	if ipv6Enabled && h.daemonConf.Addressing.IPV6 != nil {
		netIPv6, err := netip.ParseAddr(h.privNetAddressing.Address.IPV6)
		if err != nil {
			return fmt.Errorf("unable to parse private network IPv6 address: %w", err)
		}
		state.IP6 = netIPv6

		ep.Properties[endpoints.PropertyPrivNetIPv6] = h.privNetAddressing.Address.IPV6
	}

	if h.privNetAddressing.Mac != "" {
		ep.Mac = h.privNetAddressing.Mac
	}

	if !h.privNetAddressing.ActivatedAt.IsZero() {
		ep.Properties[endpoints.PropertyPrivNetActivatedAt] = h.privNetAddressing.ActivatedAt
	}

	return nil
}
