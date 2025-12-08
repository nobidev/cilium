//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

//go:build linux

package egressipconf

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"syscall"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/enterprise/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/gneigh"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// RouteTableEgressGatewayIPAM is the default table ID to use for routing rules related to Egress Gateway IPAM.
	RouteTableEgressGatewayIPAM = 2050

	// RulePriorityEgressGatewayIPAM is the priority of the rule installed by Egress Gateway IPAM to route
	// SNATed traffic to the proper egress interface.
	RulePriorityEgressGatewayIPAM = 30

	egressIPLabel = "cilium-iegp"
)

func (ops *ops) Update(ctx context.Context, _ statedb.ReadTxn, _ statedb.Revision, entry *tables.EgressIPEntry) error {
	if !entry.Addr.IsValid() {
		return fmt.Errorf("egress IP %s is not valid", entry.Addr)
	}

	iface, err := safenetlink.LinkByName(entry.Interface)
	if err != nil {
		return fmt.Errorf("failed to get device %s by name: %w", entry.Interface, err)
	}

	ops.logger.Debug("Adding address",
		logfields.Address, entry.Addr,
		logfields.Interface, entry.Interface)

	if err := netlink.AddrAdd(iface, addrForEgressIP(entry.Addr, egressIPLabel)); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("failed to add egress IP %s to interface %s: %w", entry.Addr, iface.Attrs().Name, err)
	}

	gneighIface, err := ops.gneighSender.InterfaceByIndex(iface.Attrs().Index)
	if err != nil {
		return fmt.Errorf("failed to get device %s by index: %w", entry.Interface, err)
	}

	err = ops.gneighSender.SendArp(gneighIface, entry.Addr, gneighIface.HardwareAddr())
	if err != nil {
		ops.logger.Warn("failed to send gratuitous arp reply",
			logfields.Address, entry.Addr,
			logfields.Interface, iface.Attrs().Name,
			logfields.LinkIndex, iface.Attrs().Index,
			logfields.Error, err)
	}

	ops.logger.Debug("Upserting rule",
		logfields.Address, entry.Addr)

	if err := route.ReplaceRule(ruleForEgressIP(entry.Addr)); err != nil {
		return fmt.Errorf("failed to upsert rule for address %s: %w", entry.Addr, err)
	}

	routes, err := safenetlink.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{
			Src:       entry.Addr.AsSlice(),
			LinkIndex: iface.Attrs().Index,
			Table:     RouteTableEgressGatewayIPAM,
			Protocol:  linux_defaults.RTProto,
		},
		netlink.RT_FILTER_SRC|netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
	)
	if err != nil {
		return fmt.Errorf("failed to lookup existing routes for egress IP %s and interface %s: %w", entry.Addr, iface.Attrs().Name, err)
	}

	// delete stale routes
	for _, r := range routes {
		dst, ok := netipx.FromStdIPNet(r.Dst)
		if !ok {
			return fmt.Errorf("failed to convert netlink route dst: %s", r.Dst.String())
		}

		found := false
		for _, dest := range entry.Destinations {
			if dest.String() == dst.String() {
				found = true
				break
			}
		}
		if !found {
			ops.logger.Debug("Deleting stale route",
				logfields.Address, entry.Addr,
				logfields.DestinationIP, r.Dst,
				logfields.Interface, iface.Attrs().Name)

			if err := route.DeleteV4(routeForEgressIP(entry.Addr, dst, iface)); err != nil && !errors.Is(err, syscall.ESRCH) {
				return fmt.Errorf("failed to delete route for egress IP %s and interface %s: %w", entry.Addr, iface.Attrs().Name, err)
			}
		}
	}

	// add new routes
	for _, dest := range entry.Destinations {
		found := false
		for _, r := range routes {
			dst, ok := netipx.FromStdIPNet(r.Dst)
			if !ok {
				return fmt.Errorf("failed to convert netlink route dst: %s", r.Dst.String())
			}

			if dst.String() == dest.String() {
				gw, ok := netipx.FromStdIP(r.Gw)
				if !ok && !entry.NextHop.IsValid() {
					// no next hop in the installed route and no next hop in the
					// stateDB entry, so nothing to update
					found = true
					break
				}
				if ok && entry.NextHop.IsValid() && gw == entry.NextHop {
					// next hop in the installed route and next hop in the stateDB
					// entry match, so nothing to update
					found = true
					break
				}
				// there is a mismatch between the next hop in the installed route and
				// the one in the stateDB entry, we have to upsert the updated route
			}
		}
		if !found {
			ops.logger.Debug("Upserting route",
				logfields.Address, entry.Addr,
				logfields.DestinationIP, dest,
				logfields.Interface, iface.Attrs().Name,
				logfields.NextHop, entry.NextHop)

			r := routeForEgressIP(entry.Addr, dest, iface)
			if err := route.UpsertWithoutDirectRoute(routeWithNextHop(r, entry.NextHop)); err != nil {
				return fmt.Errorf("failed to append route for egress IP %s, interface %s and next hop %s: %w", entry.Addr, iface.Attrs().Name, entry.NextHop, err)
			}
		}
	}

	return nil
}

func (ops *ops) Delete(ctx context.Context, _ statedb.ReadTxn, _ statedb.Revision, entry *tables.EgressIPEntry) error {
	iface, err := safenetlink.LinkByName(entry.Interface)
	if err != nil {
		return fmt.Errorf("failed to get device %s by name: %w", entry.Interface, err)
	}

	ops.logger.Debug("Deleting address",
		logfields.Address, entry.Addr,
		logfields.Interface, entry.Interface)

	// For compatibility reasons don't require that the IP has our label.
	if err := netlink.AddrDel(iface, addrForEgressIP(entry.Addr, "")); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
		return fmt.Errorf("failed to delete egress IP %s to interface %s: %w", entry.Addr, iface.Attrs().Name, err)
	}

	ops.logger.Debug("Deleting rule",
		logfields.Address, entry.Addr)

	if err := route.DeleteRule(netlink.FAMILY_V4, ruleForEgressIP(entry.Addr)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to delete rule for address %s: %w", entry.Addr, err)
	}

	for _, dest := range entry.Destinations {
		ops.logger.Debug("Deleting route",
			logfields.Address, entry.Addr,
			logfields.DestinationIP, dest,
			logfields.Interface, iface.Attrs().Name)

		if err := route.DeleteV4(routeForEgressIP(entry.Addr, dest, iface)); err != nil && !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("failed to delete route for egress IP %s and interface %s: %w", entry.Addr, iface.Attrs().Name, err)
		}
	}

	return nil
}

func (ops *ops) Prune(ctx context.Context, txn statedb.ReadTxn, iter iter.Seq2[*tables.EgressIPEntry, statedb.Revision]) error {
	rulesFilter, rulesMask := rulesFilter()
	rules, err := safenetlink.RuleListFiltered(netlink.FAMILY_V4, rulesFilter, rulesMask)
	if err != nil {
		return fmt.Errorf("failed to list egress-gateway IPAM rules: %w", err)
	}

	routesFilter, routesMask := routesFilter()
	routes, err := safenetlink.RouteListFiltered(netlink.FAMILY_V4, routesFilter, routesMask)
	if err != nil {
		return fmt.Errorf("failed to list egress-gateway IPAM routes: %w", err)
	}

	// There's currently no way to filter for specific labels, so we list all addresses:
	addrs, err := safenetlink.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to list egress-gateway IPAM addresses: %w", err)
	}

	// build a map of in-use egressIP -> destinations:
	egressIPs := make(map[netip.Addr]struct{})
	egressRoutes := make(map[netip.Addr][]netip.Prefix)
	for entry := range iter {
		egressIPs[entry.Addr] = struct{}{}
		egressRoutes[entry.Addr] = append(egressRoutes[entry.Addr], entry.Destinations...)
	}

	// prune rules / routes / addrs that are not part of the desired state (that is,
	// the stateDB current snapshot).
	for _, rule := range rules {
		if rule.Src == nil {
			continue
		}

		prefix, ok := netipx.FromStdIPNet(rule.Src)
		if !ok {
			return fmt.Errorf("failed to convert netlink rule src: %s", rule.Src.String())
		}
		addr := prefix.Masked().Addr()
		if _, ok := egressRoutes[addr]; ok {
			continue
		}

		ops.logger.Debug("Pruning rule",
			logfields.Address, addr)

		if err := route.DeleteRule(netlink.FAMILY_V4, ruleForEgressIP(addr)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to delete rule for address %s while pruning: %w", addr, err)
		}
	}

	for _, r := range routes {
		if r.Dst == nil {
			continue
		}

		addr, ok := netipx.FromStdIP(r.Src)
		if !ok {
			return fmt.Errorf("failed to convert netlink route src: %s", r.Src.String())
		}

		inUse := false
		if _, ok := egressRoutes[addr]; ok {
			dst, ok := netipx.FromStdIPNet(r.Dst)
			if !ok {
				return fmt.Errorf("failed to convert netlink route dst: %s", r.Dst.String())
			}
			inUse = slices.Contains(egressRoutes[addr], dst)
		}
		if inUse {
			continue
		}

		ops.logger.Debug("Pruning route",
			logfields.Address, addr,
			logfields.DestinationIP, r.Dst)

		if err := netlink.RouteDel(&netlink.Route{
			Dst:      r.Dst,
			Src:      addr.AsSlice(),
			Table:    RouteTableEgressGatewayIPAM,
			Protocol: linux_defaults.RTProto,
		}); err != nil {
			return fmt.Errorf("failed to delete route for egress IP %s while pruning: %w", addr, err)
		}
	}

	for _, a := range addrs {
		if a.Label != egressIPLabel {
			continue
		}

		addr, ok := netipx.FromStdIP(a.IP)
		if !ok {
			return fmt.Errorf("failed to convert netlink addr IP: %s", a.IP.String())
		}

		if _, ok := egressIPs[addr]; ok {
			// TODO could also check whether the IP is set on the expected interface
			continue
		}

		ops.logger.Debug("Pruning address",
			logfields.Address, addr,
			logfields.LinkIndex, a.LinkIndex)

		if err := netlink.AddrDel(nil, &a); err != nil {
			return fmt.Errorf("failed to delete egress IP %s: %w", addr, err)
		}
	}

	return nil
}

func newOps(logger *slog.Logger, gneighSender gneigh.Sender) *ops {
	return &ops{
		logger:       logger,
		gneighSender: gneighSender,
	}
}

type ops struct {
	logger       *slog.Logger
	gneighSender gneigh.Sender
}

var _ reconciler.Operations[*tables.EgressIPEntry] = &ops{}

func addrForEgressIP(addr netip.Addr, label string) *netlink.Addr {
	return &netlink.Addr{IPNet: netipx.AddrIPNet(addr), Label: label}
}

func ruleForEgressIP(addr netip.Addr) route.Rule {
	return route.Rule{
		Priority: RulePriorityEgressGatewayIPAM,
		From:     netipx.AddrIPNet(addr),
		Table:    RouteTableEgressGatewayIPAM,
		Protocol: linux_defaults.RTProto,
	}
}

func routeForEgressIP(addr netip.Addr, dest netip.Prefix, iface netlink.Link) route.Route {
	return route.Route{
		Prefix: prefixToIPNet(dest),
		Local:  addr.AsSlice(),
		Device: iface.Attrs().Name,
		Table:  RouteTableEgressGatewayIPAM,
		Proto:  linux_defaults.RTProto,
	}
}

func routeWithNextHop(r route.Route, gw netip.Addr) route.Route {
	nextHop := net.IP(gw.AsSlice())
	r.Nexthop = &nextHop
	return r
}

func prefixToIPNet(prefix netip.Prefix) net.IPNet {
	prefix = prefix.Masked()
	return net.IPNet{
		IP:   prefix.Addr().AsSlice(),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}
}

func rulesFilter() (*netlink.Rule, uint64) {
	return &netlink.Rule{
		Priority: RulePriorityEgressGatewayIPAM,
		Table:    RouteTableEgressGatewayIPAM,
		Protocol: linux_defaults.RTProto,
	}, netlink.RT_FILTER_PRIORITY | netlink.RT_FILTER_TABLE | netlink.RT_FILTER_PROTOCOL
}

func routesFilter() (*netlink.Route, uint64) {
	return &netlink.Route{
		Table:    RouteTableEgressGatewayIPAM,
		Protocol: unix.RTPROT_KERNEL,
	}, netlink.RT_FILTER_TABLE | netlink.RT_FILTER_PROTOCOL
}
