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
	"context"
	"net"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestPrivilegedBroadcastRelay(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns, err := netns.New()
	require.NoError(t, err)
	defer ns.Close()

	veth0, veth1 := setupVethPair(t, ns)

	serverErr := make(chan error, 1)
	require.NoError(t, ns.Do(func() error {
		addr, err := netlink.ParseAddr("192.168.1.1/24")
		if err != nil {
			return err
		}
		return netlink.AddrAdd(veth1, addr)
	}))

	handler := func(_ context.Context, _ cell.Health, _ uint16, req *dhcpv4.DHCPv4) (int, []*dhcpv4.DHCPv4, error) {
		if req == nil {
			return 0, nil, nil
		}
		resp, err := dhcpv4.NewReplyFromRequest(req)
		if err != nil {
			return 0, nil, err
		}
		resp.YourIPAddr = net.IPv4(192, 168, 1, 10)
		resp.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))

		resp2, err := dhcpv4.NewReplyFromRequest(req)
		if err != nil {
			return 0, nil, err
		}
		resp2.YourIPAddr = net.IPv4(192, 168, 1, 11)
		resp2.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))
		return veth1.Attrs().Index, []*dhcpv4.DHCPv4{resp, resp2}, nil
	}

	srv, err := NewServer(hivetest.Logger(t), DefaultConfig, ns, veth1.Attrs().Name, handler)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		srv.Close()
	})
	go func() {
		serverErr <- srv.Serve(ctx, nil)
	}()

	// Test the broadcast relay against the dummy DHCP server by relaying the request to
	// it via veth0.
	broadcastRelay := &broadcastRelay{
		ifname:      veth0.Attrs().Name,
		idleTimeout: 50 * time.Millisecond,
		log:         hivetest.Logger(t),
		netns:       ns,
	}
	relayFactory := &broadcastRelayFactory{relay: broadcastRelay}
	relay, err := relayFactory.RelayFor(nil)
	require.NoError(t, err)
	require.NotNil(t, relay)

	hw := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	req, err := dhcpv4.NewDiscovery(hw)
	require.NoError(t, err)
	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDiscover))

	require.Eventually(
		t,
		func() bool {
			resps, err := relay.Relay(t.Context(), 50*time.Millisecond, req)
			if err != nil {
				t.Logf("Relay(): %s", err)
				return false
			}
			if len(resps) != 2 {
				t.Logf("len(resps): %d", len(resps))
				return false
			}
			return true
		},
		time.Second,
		50*time.Millisecond,
	)

	// The socket that is now idle will eventually close
	require.Eventually(
		t,
		func() bool {
			broadcastRelay.mu.Lock()
			defer broadcastRelay.mu.Unlock()
			return broadcastRelay.conn == nil
		},
		time.Second,
		25*time.Millisecond)

	cancel()
	require.NoError(t, <-serverErr)
}
