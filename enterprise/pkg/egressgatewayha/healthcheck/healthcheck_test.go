//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package healthcheck

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

func TestPrivilegedHealthCheckerHealthyNode(t *testing.T) {
	testutils.PrivilegedTest(t)

	hc, nodeAddr := setup(t, 50*time.Millisecond, true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	events := hc.Events()

	n := nodeTypes.Node{
		Name: "test",
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   nodeAddr,
			},
		},
	}

	// node is initially marked as unhealthy
	hc.UpdateNodeList(map[string]nodeTypes.Node{n.Name: n}, sets.New[string](), sets.New[string]())

	// node should be marked as healthy
	ev := <-events
	require.Equal(t, n.Name, ev.NodeName)
	require.Equal(t, NodeReachableAgentUp, ev.Status)
	require.True(t, hc.NodeHealth(n.Name).Reachable)
	require.True(t, hc.NodeHealth(n.Name).AgentUp)
}

func TestPrivilegedHealthCheckerReachableAgentDownNode(t *testing.T) {
	testutils.PrivilegedTest(t)

	hc, nodeAddr := setup(t, 50*time.Millisecond, true,
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})

	events := hc.Events()

	n := nodeTypes.Node{
		Name: "test",
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   nodeAddr,
			},
		},
	}

	// node is initially marked as healthy
	hc.UpdateNodeList(map[string]nodeTypes.Node{n.Name: n}, sets.New(n.Name), sets.New(n.Name))

	// node should be marked as degrade because the http endpoint returns 500,
	// the ICMP request to 127.0.0.1 succeeds
	ev := <-events
	require.Equal(t, n.Name, ev.NodeName)
	require.Equal(t, NodeReachableAgentDown, ev.Status)
	require.True(t, hc.NodeHealth(n.Name).Reachable)
	require.False(t, hc.NodeHealth(n.Name).AgentUp)
}

func TestPrivilegedHealthCheckerReachableAgentDownNodeWithoutICMP(t *testing.T) {
	hc, nodeAddr := setup(t, 50*time.Millisecond, false,
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})

	events := hc.Events()

	n := nodeTypes.Node{
		Name: "test",
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   nodeAddr,
			},
		},
	}

	// node is initially marked as healthy
	hc.UpdateNodeList(map[string]nodeTypes.Node{n.Name: n}, sets.New(n.Name), sets.New(n.Name))

	// node should be marked as unreachable because the http endpoint returns 500,
	// and the ICMP probe is disabled
	ev := <-events
	require.Equal(t, n.Name, ev.NodeName)
	require.Equal(t, NodeUnReachable, ev.Status)
	require.False(t, hc.NodeHealth(n.Name).Reachable)
	require.False(t, hc.NodeHealth(n.Name).AgentUp)
}

func TestPrivilegedHealthCheckerUnhealthyNode(t *testing.T) {
	testutils.PrivilegedTest(t)

	hc, _ := setup(t, 50*time.Millisecond, true, nil)

	events := hc.Events()

	n := nodeTypes.Node{
		Name: "test",
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				// Send HTTP/ICMP requests to a non-existent address
				IP: net.ParseIP("192.168.111.111"),
			},
		},
	}

	// node is initially marked as healthy
	hc.UpdateNodeList(map[string]nodeTypes.Node{n.Name: n}, sets.New(n.Name), sets.New(n.Name))

	// node should be marked as unhealthy
	ev := <-events
	require.Equal(t, n.Name, ev.NodeName)
	require.Equal(t, NodeUnReachable, ev.Status)
	require.False(t, hc.NodeHealth(n.Name).Reachable)
	require.False(t, hc.NodeHealth(n.Name).AgentUp)
}

func setup(t *testing.T, hcTimeout time.Duration, enableICMP bool, handler http.HandlerFunc) (Healthchecker, net.IP) {
	t.Helper()

	port := 0
	addr := net.IPv4zero
	if handler != nil {
		// create a fake node health server
		ts := httptest.NewServer(handler)
		t.Cleanup(ts.Close)

		tsURL, err := url.Parse(ts.URL)
		require.NoError(t, err, "url.Parse")

		addr = net.ParseIP(tsURL.Hostname())
		require.NotNil(t, addr, "net.ParseIP")

		port, err = strconv.Atoi(tsURL.Port())
		require.NoError(t, err, "strconv.Atoi")
	}

	// create a new healthchecker
	hc := NewHealthchecker(slog.New(slog.DiscardHandler), Config{
		EgressGatewayHAHealthcheckTimeout:                         hcTimeout,
		EnableEgressGatewayHAICMPHealthProbe:                      enableICMP,
		EgressGatewayHAHealthcheckICMPHealthProbeInterval:         defaultConfig.EgressGatewayHAHealthcheckICMPHealthProbeInterval,
		EgressGatewayHAHealthcheckICMPHealthProbeFailureThreshold: defaultConfig.EgressGatewayHAHealthcheckICMPHealthProbeFailureThreshold,
		ClusterHealthPort: port,
	})

	return hc, addr
}
