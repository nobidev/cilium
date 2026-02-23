// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dhcp

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/netns"
)

func setupVethPair(t *testing.T, ns *netns.NetNS) (netlink.Link, netlink.Link) {
	t.Helper()

	var veth0 netlink.Link
	var veth1 netlink.Link
	err := ns.Do(func() error {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "veth1"},
			PeerName:  "veth0",
		}
		if err := netlink.LinkAdd(veth); err != nil {
			return err
		}
		var err error
		veth0, err = safenetlink.LinkByName("veth0")
		if err != nil {
			return err
		}
		veth1, err = safenetlink.LinkByName("veth1")
		if err != nil {
			return err
		}
		if err := netlink.LinkSetUp(veth0); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(veth1); err != nil {
			return err
		}
		return nil
	})
	require.NoError(t, err)

	return veth0, veth1
}
