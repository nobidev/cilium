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
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

func TestHealthCheckerHealthyNode(t *testing.T) {
	t.Parallel()

	hc, nodeAddr := setup(t, 50*time.Millisecond,
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
	hc.UpdateNodeList(map[string]nodeTypes.Node{n.Name: n}, sets.New[string]())

	// node should be marked as healthy
	ev := <-events
	require.Equal(t, n.Name, ev.NodeName)
	require.Equal(t, NodeHealthy, ev.Status)
	require.Eventually(t, func() bool {
		return hc.NodeIsHealthy(n.Name)
	}, 10*time.Second, 5*time.Millisecond)

}

func TestHealthCheckerUnhealthyNode(t *testing.T) {
	t.Parallel()

	hc, nodeAddr := setup(t, 50*time.Millisecond,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
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

	// node is initially marked as healthy
	hc.UpdateNodeList(map[string]nodeTypes.Node{n.Name: n}, sets.New(n.Name))

	// node should be marked as unhealthy
	ev := <-events
	require.Equal(t, n.Name, ev.NodeName)
	require.Equal(t, NodeUnhealthy, ev.Status)
	require.Eventually(t, func() bool {
		return !hc.NodeIsHealthy(n.Name)
	}, 10*time.Second, 5*time.Millisecond)
}

func setup(t *testing.T, hcTimeout time.Duration, handler http.HandlerFunc) (Healthchecker, net.IP) {
	t.Helper()

	// silence the health checker log for the test
	prev := log
	log = logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)
	t.Cleanup(func() {
		log = prev
	})

	// create a fake node health server
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	tsURL, err := url.Parse(ts.URL)
	require.NoError(t, err, "url.Parse")

	addr := net.ParseIP(tsURL.Hostname())
	require.NotNil(t, addr, "net.ParseIP")

	port, err := strconv.Atoi(tsURL.Port())
	require.NoError(t, err, "strconv.Atoi")

	// create a new healthchecker
	hc := NewHealthchecker(Config{
		EgressGatewayHAHealthcheckTimeout: hcTimeout,
		ClusterHealthPort:                 port,
	})

	return hc, addr
}
