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
	"iter"
	"log/slog"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"

	"github.com/cilium/cilium/enterprise/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/gneigh"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

const (
	egressIP1 = "192.168.1.50"
)

func filterEgressIPs(nlAddrs []netlink.Addr, label string) []netip.Addr {
	addrs := make([]netip.Addr, 0, len(nlAddrs))
	for _, nlAddr := range nlAddrs {
		if label != "" && nlAddr.Label != label {
			continue
		}

		addr, _ := netip.AddrFromSlice(nlAddr.IP)
		addrs = append(addrs, addr)
	}

	return addrs
}

func runTest(t *testing.T, prepareLink func(*netlink.Handle, netlink.Link, string)) {
	testutils.PrivilegedTest(t)

	var (
		nlh *netlink.Handle
		err error
	)

	ns := netns.NewNetNS(t)
	require.NoError(t, ns.Do(func() error {
		nlh, err = netlink.NewHandle()
		return err
	}))
	t.Cleanup(func() {
		ns.Close()
	})

	// Create a dummy device to test with
	err = nlh.LinkAdd(
		&netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: "dummy0",
			},
		},
	)
	require.NoError(t, err, "LinkAdd")
	link, err := safenetlink.WithRetryResult(func() (netlink.Link, error) {
		//nolint:forbidigo
		return nlh.LinkByName("dummy0")
	})
	require.NoError(t, err, "LinkByName")
	require.NoError(t, nlh.LinkSetUp(link))
	ifIndex := link.Attrs().Index
	ifName := link.Attrs().Name

	egressIP := netip.MustParseAddr(egressIP1)
	destinations := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("192.168.1.0/24")}

	prepareLink(nlh, link, egressIP1)

	ops := newOps(slog.New(slog.DiscardHandler), newMockGNeighSender())

	// Initial Update()
	entry := &tables.EgressIPEntry{
		Addr:         egressIP,
		Interface:    ifName,
		Destinations: destinations,
		Status:       reconciler.StatusPending(),
	}

	err = ns.Do(func() error {
		return ops.Update(context.Background(), nil, 0, entry)
	})
	require.NoError(t, err, "expected no error from initial update")

	// Egress IP should have been added to device
	nlAddrs, err := safenetlink.WithRetryResult(func() ([]netlink.Addr, error) {
		//nolint:forbidigo
		return nlh.AddrList(link, netlink.FAMILY_V4)
	})
	require.NoError(t, err, "netlink.AddrList")

	addrs := make([]netip.Addr, 0, len(nlAddrs))
	for _, nlAddr := range nlAddrs {
		addr, _ := netip.AddrFromSlice(nlAddr.IP)
		addrs = append(addrs, addr)
	}
	require.Containsf(t, addrs, egressIP, "egress IP %s not found in %s device", egressIP, ifName)

	// Source-based routing rule should have been installed for Egress IP
	rules, err := safenetlink.WithRetryResult(func() ([]netlink.Rule, error) {
		//nolint:forbidigo
		return nlh.RuleListFiltered(
			netlink.FAMILY_V4,
			&netlink.Rule{
				Priority: RulePriorityEgressGatewayIPAM,
				Src:      netipx.AddrIPNet(egressIP),
				Table:    RouteTableEgressGatewayIPAM,
				Protocol: linux_defaults.RTProto,
			},
			netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_SRC|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RuleListFiltered")
	require.Lenf(t, rules, 1, "no rule found for egress IP %s", egressIP)

	// Routes should have been installed for Egress IP
	dst_1, dst_2 := prefixToIPNet(destinations[0]), prefixToIPNet(destinations[1])

	routes, err := safenetlink.WithRetryResult(func() ([]netlink.Route, error) {
		//nolint:forbidigo
		return nlh.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{
				Dst:       &dst_1,
				Src:       egressIP.AsSlice(),
				LinkIndex: ifIndex,
				Table:     RouteTableEgressGatewayIPAM,
				Protocol:  linux_defaults.RTProto,
			},
			netlink.RT_FILTER_DST|netlink.RT_FILTER_SRC|netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RouteListFiltered")
	require.Lenf(t, routes, 1, "no route found for egress IP %s and dest %s", egressIP, destinations[0])

	routes, err = safenetlink.WithRetryResult(func() ([]netlink.Route, error) {
		//nolint:forbidigo
		return nlh.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{
				Dst:       &dst_2,
				Src:       egressIP.AsSlice(),
				LinkIndex: ifIndex,
				Table:     RouteTableEgressGatewayIPAM,
				Protocol:  linux_defaults.RTProto,
			},
			netlink.RT_FILTER_DST|netlink.RT_FILTER_SRC|netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RouteListFiltered")
	require.Lenf(t, routes, 1, "no route found for egress IP %s and dest %s", egressIP, destinations[1])

	// Further Update() with the same entry should not do anything
	err = ns.Do(func() error {
		return ops.Update(context.Background(), nil, 0, entry)
	})
	require.NoError(t, err, "expected no error from second update")

	// Update() with a different list of destinations should update the routes
	updDests := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("192.168.2.0/24")}

	updEntry := &tables.EgressIPEntry{
		Addr:         entry.Addr,
		Interface:    entry.Interface,
		Destinations: updDests,
		Status:       reconciler.StatusPending(),
	}

	err = ns.Do(func() error {
		return ops.Update(context.Background(), nil, 0, updEntry)
	})
	require.NoError(t, err, "expected no error from initial update")

	// Routes should have been installed for Egress IP
	updDst_1, updDst_2 := prefixToIPNet(updDests[0]), prefixToIPNet(updDests[1])

	routes, err = safenetlink.WithRetryResult(func() ([]netlink.Route, error) {
		//nolint:forbidigo
		return nlh.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{
				Dst:       &updDst_1,
				Src:       egressIP.AsSlice(),
				LinkIndex: ifIndex,
				Table:     RouteTableEgressGatewayIPAM,
				Protocol:  linux_defaults.RTProto,
			},
			netlink.RT_FILTER_DST|netlink.RT_FILTER_SRC|netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RouteListFiltered")
	require.Lenf(t, routes, 1, "no route found for egress IP %s and dest %s", egressIP, updDests[0])

	routes, err = safenetlink.WithRetryResult(func() ([]netlink.Route, error) {
		//nolint:forbidigo
		return nlh.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{
				Dst:       &updDst_2,
				Src:       egressIP.AsSlice(),
				LinkIndex: ifIndex,
				Table:     RouteTableEgressGatewayIPAM,
				Protocol:  linux_defaults.RTProto,
			},
			netlink.RT_FILTER_DST|netlink.RT_FILTER_SRC|netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RouteListFiltered")
	require.Lenf(t, routes, 1, "no route found for egress IP %s and dest %s", egressIP, updDests[1])

	// Non-existing devices return an error
	err = ns.Do(func() error {
		return ops.Update(context.Background(), nil, 0, &tables.EgressIPEntry{
			Addr:      egressIP,
			Interface: "non-existent",
		})
	})
	require.Error(t, err, "expected error from update of non-existing device")

	// Delete()
	err = ns.Do(func() error {
		return ops.Delete(context.Background(), nil, 0, &tables.EgressIPEntry{
			Addr:         egressIP,
			Interface:    ifName,
			Destinations: updDests,
			Status:       reconciler.StatusPending(),
		})
	})
	require.NoError(t, err, "expected no error from delete")

	// Egress IP should have been removed from device
	nlAddrs, err = safenetlink.WithRetryResult(func() ([]netlink.Addr, error) {
		//nolint:forbidigo
		return nlh.AddrList(link, netlink.FAMILY_V4)
	})
	require.NoError(t, err, "netlink.AddrList")

	addrs = make([]netip.Addr, 0, len(nlAddrs))
	for _, nlAddr := range nlAddrs {
		addr, _ := netip.AddrFromSlice(nlAddr.IP)
		addrs = append(addrs, addr)
	}
	require.NotContainsf(t, addrs, egressIP, "egress IP %s found in %s device after deletion", egressIP, ifName)

	// Source-based routing rule should have been removed for Egress IP
	rules, err = safenetlink.WithRetryResult(func() ([]netlink.Rule, error) {
		//nolint:forbidigo
		return nlh.RuleListFiltered(
			netlink.FAMILY_V4,
			&netlink.Rule{
				Priority: RulePriorityEgressGatewayIPAM,
				Src:      netipx.AddrIPNet(egressIP),
				Table:    RouteTableEgressGatewayIPAM,
				Protocol: linux_defaults.RTProto,
			},
			netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_SRC|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RuleListFiltered")
	require.Emptyf(t, rules, "rule found for egress IP %s after deletion", egressIP)

	// Routes should have been removed for Egress IP
	routes, err = safenetlink.WithRetryResult(func() ([]netlink.Route, error) {
		//nolint:forbidigo
		return nlh.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{
				Dst:       &updDst_1,
				Src:       egressIP.AsSlice(),
				LinkIndex: ifIndex,
				Table:     RouteTableEgressGatewayIPAM,
				Protocol:  linux_defaults.RTProto,
			},
			netlink.RT_FILTER_DST|netlink.RT_FILTER_SRC|netlink.RT_FILTER_IIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RouteListFiltered")
	require.Emptyf(t, routes, "route found for egress IP %s and dest %s after deletion", egressIP, updDests[0])

	routes, err = safenetlink.WithRetryResult(func() ([]netlink.Route, error) {
		//nolint:forbidigo
		return nlh.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{
				Dst:       &updDst_2,
				Src:       egressIP.AsSlice(),
				LinkIndex: ifIndex,
				Table:     RouteTableEgressGatewayIPAM,
				Protocol:  linux_defaults.RTProto,
			},
			netlink.RT_FILTER_DST|netlink.RT_FILTER_SRC|netlink.RT_FILTER_IIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RouteListFiltered")
	require.Emptyf(t, routes, "route found for egress IP %s and dest %s after deletion", egressIP, updDests[1])

	// Further Delete() should not do anything
	err = ns.Do(func() error {
		return ops.Delete(context.Background(), nil, 0, &tables.EgressIPEntry{
			Addr:         egressIP,
			Interface:    ifName,
			Destinations: updDests,
			Status:       reconciler.StatusPending(),
		})
	})
	require.NoError(t, err, "expected no error from delete")

	// Non-existing devices return an error
	err = ns.Do(func() error {
		return ops.Delete(context.Background(), nil, 0, &tables.EgressIPEntry{
			Addr:      egressIP,
			Interface: "non-existent",
		})
	})
	require.Error(t, err, "expected error from delete of non-existing device")
}

func TestPrivilegedClean(t *testing.T) {
	prepare := func(nlh *netlink.Handle, link netlink.Link, egressIP string) {}

	runTest(t, prepare)
}

// Tolerate that the egressIP is already set on the interface. Reconcile the
// other pieces.
func TestPrivilegedRestart(t *testing.T) {
	prepare := func(nlh *netlink.Handle, link netlink.Link, egressIP string) {
		addr := addrForEgressIP(netip.MustParseAddr(egressIP), egressIPLabel)
		if err := nlh.AddrAdd(link, addr); err != nil {
			t.Fatal(err)
		}
	}

	runTest(t, prepare)
}

// Tolerate that an unlabeled egressIP is already set on the interface. Reconcile the
// other pieces.
func TestPrivilegedRestartWithoutLabel(t *testing.T) {
	prepare := func(nlh *netlink.Handle, link netlink.Link, egressIP string) {
		addr := addrForEgressIP(netip.MustParseAddr(egressIP), "")
		if err := nlh.AddrAdd(link, addr); err != nil {
			t.Fatal(err)
		}
	}

	runTest(t, prepare)
}

func TestPrivilegedUpdateWithNextHop(t *testing.T) {
	testutils.PrivilegedTest(t)

	var (
		nlh *netlink.Handle
		err error
	)

	ns := netns.NewNetNS(t)
	require.NoError(t, ns.Do(func() error {
		nlh, err = netlink.NewHandle()
		return err
	}))
	t.Cleanup(func() {
		ns.Close()
	})

	// Create a dummy device to test with
	err = nlh.LinkAdd(
		&netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: "dummy0",
			},
		},
	)
	require.NoError(t, err, "LinkAdd")
	link, err := safenetlink.WithRetryResult(func() (netlink.Link, error) {
		//nolint:forbidigo
		return nlh.LinkByName("dummy0")
	})
	require.NoError(t, err, "LinkByName")
	require.NoError(t, nlh.LinkSetUp(link))
	// needed to avoid "network is unreachable" error when installing route with default gateway
	require.NoError(t, nlh.AddrAdd(link, &netlink.Addr{
		IPNet: netipx.PrefixIPNet(netip.MustParsePrefix("192.168.1.2/24")),
	}))
	ifIndex := link.Attrs().Index
	ifName := link.Attrs().Name

	egressIP := netip.MustParseAddr("192.168.1.50")
	destinations := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("192.168.2.0/24")}
	nextHop := netip.MustParseAddr("192.168.1.1")

	ops := newOps(slog.New(slog.DiscardHandler), newMockGNeighSender())

	// Initial Update()
	entry := &tables.EgressIPEntry{
		Addr:         egressIP,
		Interface:    ifName,
		Destinations: destinations,
		NextHop:      nextHop,
		Status:       reconciler.StatusPending(),
	}

	err = ns.Do(func() error {
		return ops.Update(context.Background(), nil, 0, entry)
	})
	require.NoError(t, err, "expected no error from initial update")

	// Egress IP should have been added to device
	nlAddrs, err := safenetlink.WithRetryResult(func() ([]netlink.Addr, error) {
		//nolint:forbidigo
		return nlh.AddrList(link, netlink.FAMILY_V4)
	})
	require.NoError(t, err, "netlink.AddrList")

	addrs := make([]netip.Addr, 0, len(nlAddrs))
	for _, nlAddr := range nlAddrs {
		addr, _ := netip.AddrFromSlice(nlAddr.IP)
		addrs = append(addrs, addr)
	}
	require.Containsf(t, addrs, egressIP, "egress IP %s not found in %s device", egressIP, ifName)

	// Source-based routing rule should have been installed for Egress IP
	rules, err := safenetlink.WithRetryResult(func() ([]netlink.Rule, error) {
		//nolint:forbidigo
		return nlh.RuleListFiltered(
			netlink.FAMILY_V4,
			&netlink.Rule{
				Priority: RulePriorityEgressGatewayIPAM,
				Src:      netipx.AddrIPNet(egressIP),
				Table:    RouteTableEgressGatewayIPAM,
				Protocol: linux_defaults.RTProto,
			},
			netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_SRC|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RuleListFiltered")
	require.Lenf(t, rules, 1, "no rule found for egress IP %s", egressIP)

	// Routes should have been installed for Egress IP
	dst_1, dst_2 := prefixToIPNet(destinations[0]), prefixToIPNet(destinations[1])

	routes, err := safenetlink.WithRetryResult(func() ([]netlink.Route, error) {
		//nolint:forbidigo
		return nlh.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{
				Dst:       &dst_1,
				Src:       egressIP.AsSlice(),
				Gw:        nextHop.AsSlice(),
				LinkIndex: ifIndex,
				Table:     RouteTableEgressGatewayIPAM,
				Protocol:  linux_defaults.RTProto,
			},
			netlink.RT_FILTER_DST|netlink.RT_FILTER_SRC|netlink.RT_FILTER_GW|netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RouteListFiltered")
	require.Lenf(t, routes, 1, "no route found for egress IP %s dest %s and next hop %s", egressIP, destinations[0], nextHop)

	routes, err = safenetlink.WithRetryResult(func() ([]netlink.Route, error) {
		//nolint:forbidigo
		return nlh.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{
				Dst:       &dst_2,
				Src:       egressIP.AsSlice(),
				Gw:        nextHop.AsSlice(),
				LinkIndex: ifIndex,
				Table:     RouteTableEgressGatewayIPAM,
				Protocol:  linux_defaults.RTProto,
			},
			netlink.RT_FILTER_DST|netlink.RT_FILTER_SRC|netlink.RT_FILTER_GW|netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RouteListFiltered")
	require.Lenf(t, routes, 1, "no route found for egress IP %s dest %s and next hop %s", egressIP, destinations[1], nextHop)

	// Update() with a different next hop should update the routes
	updNextHop := netip.MustParseAddr("192.168.1.2")

	updEntry := entry.Clone()
	updEntry.NextHop = updNextHop

	err = ns.Do(func() error {
		return ops.Update(context.Background(), nil, 0, updEntry)
	})
	require.NoError(t, err, "expected no error from update")

	// Routes should have been installed for Egress IP
	routes, err = safenetlink.WithRetryResult(func() ([]netlink.Route, error) {
		//nolint:forbidigo
		return nlh.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{
				Dst:       &dst_1,
				Src:       egressIP.AsSlice(),
				Gw:        updNextHop.AsSlice(),
				LinkIndex: ifIndex,
				Table:     RouteTableEgressGatewayIPAM,
				Protocol:  linux_defaults.RTProto,
			},
			netlink.RT_FILTER_DST|netlink.RT_FILTER_SRC|netlink.RT_FILTER_GW|netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RouteListFiltered")
	require.Lenf(t, routes, 1, "no route found for egress IP %s dest %s and next hop %s", egressIP, destinations[0], updNextHop)

	routes, err = safenetlink.WithRetryResult(func() ([]netlink.Route, error) {
		//nolint:forbidigo
		return nlh.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{
				Dst:       &dst_2,
				Src:       egressIP.AsSlice(),
				Gw:        updNextHop.AsSlice(),
				LinkIndex: ifIndex,
				Table:     RouteTableEgressGatewayIPAM,
				Protocol:  linux_defaults.RTProto,
			},
			netlink.RT_FILTER_DST|netlink.RT_FILTER_SRC|netlink.RT_FILTER_GW|netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RouteListFiltered")
	require.Lenf(t, routes, 1, "no route found for egress IP %s dest %s and next hop %s", egressIP, destinations[1], updNextHop)

	// Update() without a next hop should update the routes leaving the gateway empty
	noGwEntry := updEntry.Clone()
	noGwEntry.NextHop = netip.Addr{}

	err = ns.Do(func() error {
		return ops.Update(context.Background(), nil, 0, noGwEntry)
	})
	require.NoError(t, err, "expected no error from update")

	// Routes should have been installed for Egress IP
	routes, err = safenetlink.WithRetryResult(func() ([]netlink.Route, error) {
		//nolint:forbidigo
		return nlh.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{
				Dst:       &dst_1,
				Src:       egressIP.AsSlice(),
				LinkIndex: ifIndex,
				Table:     RouteTableEgressGatewayIPAM,
				Protocol:  linux_defaults.RTProto,
			},
			netlink.RT_FILTER_DST|netlink.RT_FILTER_SRC|netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RouteListFiltered")
	require.Lenf(t, routes, 1, "no route found for egress IP %s dest %s", egressIP, destinations[0])
	gw1, _ := netipx.FromStdIP(routes[0].Gw)
	require.False(t, gw1.IsValid(), "expected no next hop for route with egress IP %s dest %s, found %s", egressIP, destinations[0], routes[0].Gw)

	routes, err = safenetlink.WithRetryResult(func() ([]netlink.Route, error) {
		//nolint:forbidigo
		return nlh.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{
				Dst:       &dst_2,
				Src:       egressIP.AsSlice(),
				LinkIndex: ifIndex,
				Table:     RouteTableEgressGatewayIPAM,
				Protocol:  linux_defaults.RTProto,
			},
			netlink.RT_FILTER_DST|netlink.RT_FILTER_SRC|netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RouteListFiltered")
	require.Lenf(t, routes, 1, "no route found for egress IP %s dest %s and next hop %s", egressIP, destinations[1], updNextHop)
	gw2, _ := netipx.FromStdIP(routes[0].Gw)
	require.False(t, gw2.IsValid(), "expected no next hop for route with egress IP %s dest %s, found %s", egressIP, destinations[0], routes[0].Gw)
}

func TestPrivilegedPrune(t *testing.T) {
	testutils.PrivilegedTest(t)

	var (
		nlh *netlink.Handle
		err error
	)

	ns := netns.NewNetNS(t)
	require.NoError(t, ns.Do(func() error {
		nlh, err = netlink.NewHandle()
		return err
	}))
	t.Cleanup(func() {
		ns.Close()
	})

	// Create a dummy device to test with
	err = nlh.LinkAdd(
		&netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: "dummy0",
			},
		},
	)
	require.NoError(t, err, "LinkAdd")
	link, err := safenetlink.WithRetryResult(func() (netlink.Link, error) {
		//nolint:forbidigo
		return nlh.LinkByName("dummy0")
	})
	require.NoError(t, err, "LinkByName")
	require.NoError(t, nlh.LinkSetUp(link))
	ifName := link.Attrs().Name
	ifIndex := link.Attrs().Index

	ops := newOps(slog.New(slog.DiscardHandler), newMockGNeighSender())

	egressIP_1 := netip.MustParseAddr("192.168.1.50")
	destinations_1_1 := netip.MustParsePrefix("192.168.1.0/24")
	destinations_1_2 := netip.MustParsePrefix("192.168.2.0/24")
	egressIP_2 := netip.MustParseAddr("192.168.1.100")
	destinations_2_1 := netip.MustParsePrefix("192.168.3.0/24")
	destinations_2_2 := netip.MustParsePrefix("192.168.4.0/24")

	entries := []*tables.EgressIPEntry{
		{
			Addr:         egressIP_1,
			Interface:    ifName,
			Destinations: []netip.Prefix{destinations_1_1, destinations_1_2},
		},
		{
			Addr:         egressIP_2,
			Interface:    ifName,
			Destinations: []netip.Prefix{destinations_2_1, destinations_2_2},
		},
	}

	// call Update() to reconcile network config as specified in the entries
	for _, entry := range entries {
		err = ns.Do(func() error {
			return ops.Update(context.Background(), nil, 0, entry)
		})
		require.NoError(t, err, "ops.Update")
	}

	// build a fake iterator containing entries for:
	//
	// <egressIP_2, destinations_2_1>
	// <egressIP_2, destinations_2_2>
	//
	// then call Prune
	err = ns.Do(func() error {
		return ops.Prune(context.Background(), nil, newFakeIterator(&tables.EgressIPEntry{
			Addr:         egressIP_2,
			Interface:    ifName,
			Destinations: []netip.Prefix{destinations_2_1, destinations_2_2},
		}))
	})
	require.NoError(t, err, "ops.Prune")

	// egressIP_1 should have been deleted
	nlAddrs, err := safenetlink.WithRetryResult(func() ([]netlink.Addr, error) {
		//nolint:forbidigo
		return nlh.AddrList(link, netlink.FAMILY_V4)
	})
	require.NoError(t, err, "netlink.AddrList")
	addrs := filterEgressIPs(nlAddrs, "")
	require.ElementsMatch(t, addrs, []netip.Addr{egressIP_2})

	// only the rule for egressIP_1 should have been deleted
	rules, err := safenetlink.WithRetryResult(func() ([]netlink.Rule, error) {
		//nolint:forbidigo
		return nlh.RuleListFiltered(
			netlink.FAMILY_V4,
			&netlink.Rule{
				Priority: RulePriorityEgressGatewayIPAM,
				Table:    RouteTableEgressGatewayIPAM,
				Protocol: linux_defaults.RTProto,
			},
			netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RuleListFiltered")
	require.Len(t, rules, 1)
	require.Equal(t, netipx.AddrIPNet(egressIP_2), rules[0].Src)

	// only routes for egressIP_1 should have been deleted
	routes, err := safenetlink.WithRetryResult(func() ([]netlink.Route, error) {
		//nolint:forbidigo
		return nlh.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{
				LinkIndex: ifIndex,
				Table:     RouteTableEgressGatewayIPAM,
				Protocol:  linux_defaults.RTProto,
			},
			netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RouteListFiltered")
	require.Len(t, routes, 2)
	require.Equal(t, net.IP(egressIP_2.AsSlice()), routes[0].Src)
	require.Equal(t, net.IP(egressIP_2.AsSlice()), routes[1].Src)
	found := []*net.IPNet{routes[0].Dst, routes[1].Dst}
	require.ElementsMatch(t, []*net.IPNet{netipx.PrefixIPNet(destinations_2_1), netipx.PrefixIPNet(destinations_2_2)}, found)

	// call again Update() to reconcile network config as specified in the entries
	for _, entry := range entries {
		err = ns.Do(func() error {
			return ops.Update(context.Background(), nil, 0, entry)
		})
		require.NoError(t, err, "ops.Update")
	}

	// build a fake iterator containing an entry for:
	//
	// <egressIP_1, destinations_1_1>
	//
	// then call Prune
	err = ns.Do(func() error {
		return ops.Prune(context.Background(), nil, newFakeIterator(
			&tables.EgressIPEntry{
				Addr:         egressIP_1,
				Interface:    ifName,
				Destinations: []netip.Prefix{destinations_1_1},
			}))
	})
	require.NoError(t, err, "ops.Prune")

	// egressIP_2 should have been deleted
	nlAddrs, err = safenetlink.WithRetryResult(func() ([]netlink.Addr, error) {
		//nolint:forbidigo
		return nlh.AddrList(link, netlink.FAMILY_V4)
	})
	require.NoError(t, err, "netlink.AddrList")
	addrs = filterEgressIPs(nlAddrs, "")
	require.ElementsMatch(t, addrs, []netip.Addr{egressIP_1})

	// only the rule for egressIP_2 should have been deleted
	rules, err = safenetlink.WithRetryResult(func() ([]netlink.Rule, error) {
		//nolint:forbidigo
		return nlh.RuleListFiltered(
			netlink.FAMILY_V4,
			&netlink.Rule{
				Priority: RulePriorityEgressGatewayIPAM,
				Table:    RouteTableEgressGatewayIPAM,
				Protocol: linux_defaults.RTProto,
			},
			netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RuleListFiltered")
	require.Len(t, rules, 1)
	require.Equal(t, netipx.AddrIPNet(egressIP_1), rules[0].Src)

	// only routes for:
	//
	// <egressIP_1, destination_1_2>
	// <egressIP_2, destination_2_2>
	// <egressIP_2, destination_2_2>
	//
	// should have been deleted
	routes, err = safenetlink.WithRetryResult(func() ([]netlink.Route, error) {
		//nolint:forbidigo
		return nlh.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{
				LinkIndex: ifIndex,
				Table:     RouteTableEgressGatewayIPAM,
				Protocol:  linux_defaults.RTProto,
			},
			netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RouteListFiltered")
	require.Len(t, routes, 1)
	require.Equal(t, net.IP(egressIP_1.AsSlice()), routes[0].Src)
	require.Equal(t, netipx.PrefixIPNet(destinations_1_1), routes[0].Dst)

	// build a fake empty iterator and call Prune
	err = ns.Do(func() error {
		return ops.Prune(context.Background(), nil, newFakeIterator())
	})
	require.NoError(t, err, "ops.Prune")

	// egress IPs should have been deleted
	nlAddrs, err = safenetlink.WithRetryResult(func() ([]netlink.Addr, error) {
		//nolint:forbidigo
		return nlh.AddrList(link, netlink.FAMILY_V4)
	})
	require.NoError(t, err, "netlink.AddrList")
	addrs = filterEgressIPs(nlAddrs, "")
	require.Empty(t, addrs)

	// all rules should have been deleted
	rules, err = safenetlink.WithRetryResult(func() ([]netlink.Rule, error) {
		//nolint:forbidigo
		return nlh.RuleListFiltered(
			netlink.FAMILY_V4,
			&netlink.Rule{
				Priority: RulePriorityEgressGatewayIPAM,
				Table:    RouteTableEgressGatewayIPAM,
				Protocol: linux_defaults.RTProto,
			},
			netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RuleListFiltered")
	require.Empty(t, rules)

	// all routes should have been deleted
	routes, err = safenetlink.WithRetryResult(func() ([]netlink.Route, error) {
		//nolint:forbidigo
		return nlh.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{
				LinkIndex: ifIndex,
				Table:     RouteTableEgressGatewayIPAM,
				Protocol:  linux_defaults.RTProto,
			},
			netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RouteListFiltered")
	require.Empty(t, routes)

	// *** Now validate that we don't prune old-style IPs:

	// Add an unlabeled IP, and reconcile the rest:
	addr := addrForEgressIP(egressIP_2, "")
	if err = nlh.AddrAdd(link, addr); err != nil {
		t.Fatal(err)
	}

	// call again Update() to reconcile network config as specified in the entries
	for _, entry := range entries {
		err = ns.Do(func() error {
			return ops.Update(context.Background(), nil, 0, entry)
		})
		require.NoError(t, err, "ops.Update")
	}

	// build a fake empty iterator and call Prune
	err = ns.Do(func() error {
		return ops.Prune(context.Background(), nil, newFakeIterator())
	})
	require.NoError(t, err, "ops.Prune")

	// egressIP_2 should still be there
	nlAddrs, err = safenetlink.WithRetryResult(func() ([]netlink.Addr, error) {
		//nolint:forbidigo
		return nlh.AddrList(link, netlink.FAMILY_V4)
	})
	require.NoError(t, err, "netlink.AddrList")
	addrs = filterEgressIPs(nlAddrs, "")
	require.ElementsMatch(t, addrs, []netip.Addr{egressIP_2})

	// all rules should have been deleted
	rules, err = safenetlink.WithRetryResult(func() ([]netlink.Rule, error) {
		//nolint:forbidigo
		return nlh.RuleListFiltered(
			netlink.FAMILY_V4,
			&netlink.Rule{
				Priority: RulePriorityEgressGatewayIPAM,
				Table:    RouteTableEgressGatewayIPAM,
				Protocol: linux_defaults.RTProto,
			},
			netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RuleListFiltered")
	require.Empty(t, rules)

	// all routes should have been deleted
	routes, err = safenetlink.WithRetryResult(func() ([]netlink.Route, error) {
		//nolint:forbidigo
		return nlh.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{
				LinkIndex: ifIndex,
				Table:     RouteTableEgressGatewayIPAM,
				Protocol:  linux_defaults.RTProto,
			},
			netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
		)
	})
	require.NoError(t, err, "RouteListFiltered")
	require.Empty(t, routes)
}

func newFakeIterator(objs ...*tables.EgressIPEntry) iter.Seq2[*tables.EgressIPEntry, statedb.Revision] {
	return func(yield func(*tables.EgressIPEntry, statedb.Revision) bool) {
		for _, obj := range objs {
			if !yield(obj, 0) {
				return
			}
		}
	}
}

func newMockGNeighSender() gneigh.Sender {
	return &mockGNeighSender{}
}

type mockGNeighSender struct{}

func (gs *mockGNeighSender) SendArp(iface gneigh.Interface, ip netip.Addr, srcHW net.HardwareAddr) error {
	return nil
}

func (gs *mockGNeighSender) SendNd(iface gneigh.Interface, ip netip.Addr, srcHW net.HardwareAddr) error {
	return nil
}

func (gs *mockGNeighSender) NewArpSender(iface gneigh.Interface) (gneigh.ArpSender, error) {
	return &mockArpSender{}, nil
}

func (gs *mockGNeighSender) NewNdSender(iface gneigh.Interface) (gneigh.NdSender, error) {
	return &mockNdSender{}, nil
}

func (gs *mockGNeighSender) InterfaceByIndex(idx int) (gneigh.Interface, error) {
	return gneigh.InterfaceFromNetInterface(&net.Interface{}), nil
}

type mockArpSender struct{}

func (as *mockArpSender) Send(ip netip.Addr, srcHW net.HardwareAddr) error {
	return nil
}

func (as *mockArpSender) Close() error {
	return nil
}

type mockNdSender struct{}

func (ns *mockNdSender) Send(ip netip.Addr, srcHW net.HardwareAddr) error {
	return nil
}

func (ns *mockNdSender) Close() error {
	return nil
}
