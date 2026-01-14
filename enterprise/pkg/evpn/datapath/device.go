//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package datapath

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/mac"
)

// setupEvpnVxlanDevice ensures the evpn device is created with the given
// port, and MTU.
//
// Changing the port will recreate the device. Changing the MTU will modify the
// device without recreating it.
func setupEvpnVxlanDevice(logger *slog.Logger, sysctl sysctl.Sysctl, device string, port uint16, mtu int) error {
	mac, err := mac.GenerateRandMAC()
	if err != nil {
		return fmt.Errorf("failed to generate random MAC address for evpn vxlan device: %w", err)
	}

	dev := &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:         device,
			MTU:          mtu,
			HardwareAddr: net.HardwareAddr(mac),
		},
		FlowBased: true,
		Port:      int(port),
	}

	if l, err := safenetlink.LinkByName(dev.Attrs().Name); err == nil {
		// Recreate the device with the correct destination port. Modifying the device
		// without recreating it is not supported.
		vxlan, ok := l.(*netlink.Vxlan)
		if !ok || vxlan.Port != int(port) {
			if err := netlink.LinkDel(l); err != nil {
				return fmt.Errorf("failed deleting outdated evpn vxlan device: %w", err)
			}
		}
	}

	_, err = loader.EnsureDevice(logger, sysctl, dev)
	if err != nil {
		return fmt.Errorf("failed creating evpn vxlan device %s: %w", dev.Attrs().Name, err)
	}

	return nil
}

// removeEvpnVxlanDevice ensures the evpn device is removed.
func removeEvpnVxlanDevice(device string) error {
	if device == "" {
		return nil
	}
	if err := loader.RemoveDevice(device); err != nil {
		return fmt.Errorf("failed removing device %s: %w", device, err)
	}
	return nil
}
