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
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
)

func NextHopFromDefaultRoute(iface string) (netip.Addr, error) {
	link, err := safenetlink.LinkByName(iface)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to get device %s by name: %w", iface, err)
	}

	routes, err := safenetlink.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Table:     unix.RT_TABLE_MAIN,
			Dst: &net.IPNet{
				IP:   net.IPv4(0, 0, 0, 0),
				Mask: net.CIDRMask(0, 8*net.IPv4len),
			},
		},
		netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST,
	)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to get default route for iface %s: %w", iface, err)
	}
	// should never happen if err == nil, but better safe than sorry
	if len(routes) == 0 {
		return netip.Addr{}, fmt.Errorf("no default route available for iface %s: %w", iface, err)
	}

	gw, ok := netipx.FromStdIP(routes[0].Gw)
	if !ok {
		return netip.Addr{}, fmt.Errorf("unable to convert next hop address for iface %s: %w", iface, err)
	}

	return gw, nil
}
