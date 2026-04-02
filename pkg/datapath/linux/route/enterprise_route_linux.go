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

package route

import (
	"fmt"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/time"
)

// UpsertWithoutDirectRoute adds or updates a Linux kernel route.
//
// Differently from Update it does not insert a direct route if next hop is specified.
//
// Due to a bug in the Linux kernel, the prefix route is attempted to be
// updated RouteReplaceMaxTries with an interval of RouteReplaceRetryInterval.
// This is a workaround for a race condition in which the direct route to the
// nexthop is not available immediately and the prefix route can fail with
// EINVAL if the Netlink calls are issued in short order.
//
// An error is returned if the route can not be added or updated.
func UpsertWithoutDirectRoute(route Route) error {
	link, err := safenetlink.LinkByName(route.Device)
	if err != nil {
		return fmt.Errorf("unable to lookup interface %s: %w", route.Device, err)
	}

	// Can't add local routes to an interface that's down ('lo' in new netns).
	if link.Attrs().OperState == netlink.OperDown {
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("unable to set interface up: %w", err)
		}
	}

	routeSpec := route.getNetlinkRoute()
	routeSpec.LinkIndex = link.Attrs().Index

	err = fmt.Errorf("routeReplace not called yet")

	// Workaround: See description of this function
	for i := 0; err != nil && i < RouteReplaceMaxTries; i++ {
		err = netlink.RouteReplace(&routeSpec)
		if err == nil {
			break
		}
		time.Sleep(RouteReplaceRetryInterval)
	}

	if err != nil {
		return fmt.Errorf("unable to install route: %w", err)
	}

	return nil
}
