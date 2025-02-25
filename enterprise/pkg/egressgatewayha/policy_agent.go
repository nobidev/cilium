//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/enterprise/datapath/tables"
	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha/egressipconf"
	"github.com/cilium/cilium/pkg/datapath/linux/netdevice"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// azActiveGatewayIPs is a list of active gateway IPs for a particular AZ.
// In addition to the list of IPs, localNodeConfiguredAsGateway specifies if the
// local node is configured as a gateway for the AZ.
type azActiveGatewayIPs struct {
	// list of active gateway IPs for a given AZ
	gatewayIPs []netip.Addr

	// with AZ affinity enabled, within an egress group, the same node can be
	// be configured as gateway for some endpoints, while being not enabled
	// for others.
	//
	// We track this information to determine correctly the egress IP to
	// use for a given endpoint.
	localNodeConfiguredAsGateway bool
}

// gatewayConfig is the gateway configuration derived at runtime from a policy.
//
// Some of these fields are derived from the running system as the policy may
// specify only the egress IP (and so we need to figure out which interface has
// that IP assigned to) or the interface (and in this case we need to find the
// first IPv4 assigned to that).
type gatewayConfig struct {
	// ifaceName is the name of the interface used to SNAT traffic
	ifaceName string

	// egressIfindex is the ifindex of the interface used to SNAT traffic
	egressIfindex uint32

	// egressIP is the IP used to SNAT traffic
	egressIP netip.Addr

	// activeGatewayIPs is a slice of node IPs that are actively working as
	// egress gateways
	activeGatewayIPs []netip.Addr

	// activeGatewayIPsByAZ maps AZs to a slice of node IPs that are
	// actively working as egress gateway for that AZ
	activeGatewayIPsByAZ map[string]azActiveGatewayIPs

	// healthyGatewayIPs is the entire pool of healthy nodes that can act as
	// egress gateway for the given policy.
	// Not all of them may be actively acting as gateway since with the
	// maxGatewayNodes policy directive we can select a subset of them
	healthyGatewayIPs []netip.Addr

	// azAffinity configures the AZ affinity mode for the policy
	azAffinity azAffinityMode

	// localNodeConfiguredAsGateway tells if the local node belongs to the
	// pool of egress gateway node for this config.
	// This information is used to make sure the node does not get selected
	// multiple times by different egress groups
	localNodeConfiguredAsGateway bool
}

// matchesEndpointLabels determines if the given endpoint is a match for the
// policy config based on matching labels.
func (config *PolicyConfig) matchesEndpointLabels(endpointInfo *endpointMetadata) bool {
	labelsToMatch := k8sLabels.Set(endpointInfo.labels)
	for _, selector := range config.endpointSelectors {
		if selector.Matches(labelsToMatch) {
			return true
		}
	}
	return false
}

// updateMatchedEndpointIDs update the policy's cache of matched endpoint IDs
func (config *PolicyConfig) updateMatchedEndpointIDs(epDataStore map[endpointID]*endpointMetadata) {
	config.matchedEndpoints = make(map[endpointID]*endpointMetadata)

	for _, endpoint := range epDataStore {
		if config.matchesEndpointLabels(endpoint) {
			config.matchedEndpoints[endpoint.id] = endpoint
		}
	}
}

func (config *PolicyConfig) regenerateGatewayConfig(manager *Manager) {
	config.gatewayConfig = gatewayConfig{
		egressIP:             netip.IPv4Unspecified(),
		activeGatewayIPs:     []netip.Addr{},
		activeGatewayIPsByAZ: map[string]azActiveGatewayIPs{},
		healthyGatewayIPs:    []netip.Addr{},
		azAffinity:           config.azAffinity,
	}

	if len(config.groupStatuses) == 0 {
		return
	}

	localNode, err := manager.localNodeStore.Get(context.TODO())
	if err != nil {
		log.Error("Failed to get local node store")
		return
	}

	localNodeK8sAddr, ok := netipx.FromStdIP(localNode.GetK8sNodeIP())
	if !ok {
		log.Error("Failed to parse local node IP")
		return
	}

	var egressIPs []gwEgressIPConfig

	gwc := &config.gatewayConfig
	for groupIndex, gc := range config.groupConfigs {
		groupStatus := &config.groupStatuses[groupIndex]
		// We use the local node IP to determine if the current node
		// matches the list of active gateway IPs
		localNodeMatchesGatewayIP := false

		if !gwc.azAffinity.enabled() {
			gwc.activeGatewayIPs = append(gwc.activeGatewayIPs, groupStatus.activeGatewayIPs...)

			if slices.Contains(groupStatus.activeGatewayIPs, localNodeK8sAddr) {
				localNodeMatchesGatewayIP = true
			}
		} else {
			for az, gwIPs := range groupStatus.activeGatewayIPsByAZ {
				azGwIPs, ok := gwc.activeGatewayIPsByAZ[az]
				if !ok {
					azGwIPs = azActiveGatewayIPs{
						gatewayIPs: []netip.Addr{},
					}
				}
				azGwIPs.gatewayIPs = append(azGwIPs.gatewayIPs, gwIPs...)

				if slices.Contains(gwIPs, localNodeK8sAddr) {
					localNodeMatchesGatewayIP = true
					azGwIPs.localNodeConfiguredAsGateway = true
				}

				gwc.activeGatewayIPsByAZ[az] = azGwIPs
			}
		}
		gwc.healthyGatewayIPs = append(gwc.healthyGatewayIPs, groupStatus.healthyGatewayIPs...)

		logger := log.WithFields(logrus.Fields{
			logfields.IsovalentEgressGatewayPolicyName: config.id,
			logfields.Interface:                        gc.iface,
			logfields.EgressIP:                         gc.egressIP,
		})

		if localNodeMatchesGatewayIP {
			// If localNodeConfiguredAsGateway is already set it means that another
			// egress group for the same policy has already selected it as gateway. In
			// this case don't regenerate a new gatewayConfig and return an error
			if gwc.localNodeConfiguredAsGateway {
				logger.WithError(err).Error("Local node selected by multiple egress gateway groups from the same policy")
				continue
			}

			if egressIP, found := groupStatus.egressIPByGatewayIP[localNodeK8sAddr]; found {
				var (
					iface netlink.Link
					err   error
				)
				if gc.iface != "" {
					iface, err = safenetlink.LinkByName(gc.iface)
				} else {
					iface, err = route.NodeDeviceWithDefaultRoute(true, false)
				}
				if err != nil {
					logger.WithError(err).Error("Failed to find interface while updating node egress IP config")
					continue
				}

				egressIPs = append(egressIPs, gwEgressIPConfig{egressIP, iface.Attrs().Name})

				gwc.ifaceName = iface.Attrs().Name
				gwc.egressIfindex = uint32(iface.Attrs().Index)
				gwc.egressIP = egressIP
			} else if err := gwc.deriveFromGroupConfig(&gc); err != nil {
				logger.WithError(err).Error("Failed to derive policy gateway configuration")
				continue
			}

			gwc.localNodeConfiguredAsGateway = true
		}
	}

	// upsert all the egress configs <egress IP, egress interface, destination CIDRs>
	// from the current status of the policy and remove the configs from the previous policy status
	nextEgressIPs := sets.New(egressIPs...)
	curEgressIPs := manager.egressConfigsByPolicy[config.id]
	toDel := curEgressIPs.Difference(nextEgressIPs)
	updateEgressIPsConfig(manager.db, manager.egressIPTable, nextEgressIPs, toDel, config.dstCIDRs)
	manager.egressConfigsByPolicy[config.id] = nextEgressIPs

}

func updateEgressIPsConfig(
	db *statedb.DB,
	table statedb.RWTable[*tables.EgressIPEntry],
	toUpsert, toDel sets.Set[gwEgressIPConfig],
	destinations []netip.Prefix,
) {
	txn := db.WriteTxn(table)
	defer txn.Abort()

	for _, config := range toDel.UnsortedList() {
		table.Delete(txn, &tables.EgressIPEntry{
			Addr:      config.addr,
			Interface: config.iface,
		})
	}

	// cache next hops to reduce netlink overhead
	nextHops := make(map[string]netip.Addr)
	for _, config := range toUpsert.UnsortedList() {
		if _, ok := nextHops[config.iface]; ok {
			continue
		}
		nextHop, err := egressipconf.NextHopFromDefaultRoute(config.iface)
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.Interface: config.iface,
			}).Warning("Failed to find next hop to use for egress gateway IPAM route, connectivity to external endpoints might be broken for all SNATed traffic through the interface.")
			continue
		}
		nextHops[config.iface] = nextHop
	}

	for _, config := range toUpsert.UnsortedList() {
		entry := tables.EgressIPEntry{
			Addr:         config.addr,
			Interface:    config.iface,
			Destinations: destinations,
			Status:       reconciler.StatusPending(),
		}
		if nextHop, ok := nextHops[config.iface]; ok {
			entry.NextHop = nextHop
		}
		table.Insert(txn, &entry)
	}

	txn.Commit()
}

// deriveFromGroupConfig retrieves all the missing gateway configuration data
// (such as egress IP or interface) given a policy group config
func (gwc *gatewayConfig) deriveFromGroupConfig(gc *groupConfig) error {
	var err error

	switch {
	case gc.iface != "":
		// If the group config specifies an interface, use the first IPv4 assigned to that
		// interface as egress IP
		gwc.ifaceName = gc.iface

		iface, err := safenetlink.LinkByName(gc.iface)
		if err != nil {
			gwc.egressIP = EgressIPNotFoundIPv4
			return fmt.Errorf("failed to retrieve egress interface %s: %w", gc.iface, err)
		}

		gwc.egressIfindex = uint32(iface.Attrs().Index)

		gwc.egressIP, err = netdevice.GetIfaceFirstIPv4Address(gc.iface)
		if err != nil {
			gwc.egressIP = EgressIPNotFoundIPv4
			return fmt.Errorf("failed to retrieve IPv4 address for egress interface: %w", err)
		}
	case gc.egressIP.IsValid():
		// If the group config specifies an egress IP, use the interface with that IP as egress
		// interface
		gwc.egressIP = gc.egressIP
		// Don't apply ifindex-based BPF forwarding, and instead defer to IP routing:
		gwc.egressIfindex = 0
		gwc.ifaceName, err = netdevice.GetIfaceWithIPv4Address(gc.egressIP)
		if err != nil {
			return fmt.Errorf("failed to retrieve interface with egress IP: %w", err)
		}
	default:
		// If the group config doesn't specify any egress IP or interface, use
		// the interface with the IPv4 default route
		iface, err := route.NodeDeviceWithDefaultRoute(true, false)
		if err != nil {
			gwc.egressIP = EgressIPNotFoundIPv4
			return fmt.Errorf("failed to find interface with default route: %w", err)
		}

		gwc.ifaceName = iface.Attrs().Name
		gwc.egressIfindex = uint32(iface.Attrs().Index)
		gwc.egressIP, err = netdevice.GetIfaceFirstIPv4Address(gwc.ifaceName)
		if err != nil {
			gwc.egressIP = EgressIPNotFoundIPv4
			return fmt.Errorf("failed to retrieve IPv4 address for egress interface: %w", err)
		}
	}

	return nil
}

// gatewayConfigForEndpoint returns the configuration of active gateway IPs
// and egress IP for a given endpoint
//
// If the AZ resolution fails, this method will fallback to the non AZ-aware list of active gateway IPs
func (gwc *gatewayConfig) gatewayConfigForEndpoint(manager *Manager, endpoint *endpointMetadata) ([]netip.Addr, netip.Addr, uint32) {
	egressIP := netip.IPv4Unspecified()
	egressIfindex := uint32(0)

	if gwc.localNodeConfiguredAsGateway {
		egressIP = gwc.egressIP
		egressIfindex = gwc.egressIfindex
	}

	if !gwc.azAffinity.enabled() {
		return gwc.activeGatewayIPs, egressIP, egressIfindex
	}

	endpointNode, ok := manager.nodesByIP[endpoint.nodeIP.String()]
	if !ok {
		log.WithFields(logrus.Fields{
			logfields.EndpointID: endpoint.id,
			logfields.K8sNodeIP:  endpoint.nodeIP.String(),
		}).Error("cannot find endpoint's node")

		//fallback to the non AZ-aware list of gateway IPs
		return gwc.activeGatewayIPs, egressIP, egressIfindex
	}

	az, ok := endpointNode.Labels[core_v1.LabelTopologyZone]
	if !ok {
		log.WithFields(logrus.Fields{
			logfields.EndpointID: endpoint.id,
			logfields.K8sNodeIP:  endpoint.nodeIP.String(),
		}).Errorf("missing node's AZ label")

		//fallback to the non AZ-aware list of gateway IPs
		return gwc.activeGatewayIPs, egressIP, egressIfindex
	}

	egressIP = netip.IPv4Unspecified()
	egressIfindex = 0
	if gwc.activeGatewayIPsByAZ[az].localNodeConfiguredAsGateway {
		egressIP = gwc.egressIP
		egressIfindex = gwc.egressIfindex
	}

	return gwc.activeGatewayIPsByAZ[az].gatewayIPs, egressIP, egressIfindex
}

// forEachEndpointAndCIDR iterates through each combination of endpoints and
// destination/excluded CIDRs of the receiver policy, and for each of them it
// calls the f callback function passing the given endpoint and CIDR, together
// with a boolean value indicating if the CIDR belongs to the excluded ones and
// the gatewayConfig of the receiver policy
func (config *PolicyConfig) forEachEndpointAndCIDR(f func(*endpointMetadata, netip.Prefix, bool, *gatewayConfig)) {
	for _, endpoint := range config.matchedEndpoints {
		isExcludedCIDR := false
		for _, dstCIDR := range config.dstCIDRs {
			f(endpoint, dstCIDR, isExcludedCIDR, &config.gatewayConfig)
		}

		isExcludedCIDR = true
		for _, excludedCIDR := range config.excludedCIDRs {
			f(endpoint, excludedCIDR, isExcludedCIDR, &config.gatewayConfig)
		}
	}
}
