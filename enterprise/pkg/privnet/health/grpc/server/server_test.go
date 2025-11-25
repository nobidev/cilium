//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package server

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"slices"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	api "github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/api/v1"
	"github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	notypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

type (
	PN  = tables.PrivateNetwork
	PNI = tables.PrivateNetworkInterface
	AN  = tables.ActiveNetwork
	WN  = tables.WorkloadNode
)

const (
	// timeout is the timeout when waiting for an event to occur.
	timeout = 1 * time.Second

	// shortTimeout is a shorter timeout when checking that an event didn't occur.
	shortTimeout = 100 * time.Millisecond
)

func fixture(t *testing.T) (*statedb.DB, statedb.RWTable[PN], statedb.RWTable[AN], *server) {
	var db = statedb.New()

	networks, err := tables.NewPrivateNetworksTable(db)
	require.NoError(t, err, "tables.NewPrivateNetworksTable")

	actnets, err := tables.NewActiveNetworksTable(db)
	require.NoError(t, err, "tables.NewActiveNetworksTable")

	return db, networks, actnets, newServer(serverParams{
		Logger:   hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)),
		DB:       db,
		Networks: networks,
		Table:    actnets,
	})
}

type mockStream[Req, Res any] struct {
	ctx  context.Context
	recv chan mockStreamReq[Req]
	sent chan *Res
}

type mockStreamReq[Req any] struct {
	data *Req
	err  error
}

var _ grpc.ServerStreamingServer[string] = mockStream[int, string]{}
var _ grpc.BidiStreamingServer[int, string] = mockStream[int, string]{}

func newMockStream[Req, Res any](ctx context.Context) mockStream[Req, Res] {
	return mockStream[Req, Res]{
		ctx:  ctx,
		recv: make(chan mockStreamReq[Req], 10),
		sent: make(chan *Res, 10),
	}
}

func (m mockStream[Req, Res]) Recv() (*Req, error) {
	req := <-m.recv
	return req.data, req.err
}

func (m mockStream[Req, Res]) Send(res *Res) error {
	m.sent <- res
	return nil
}

func (m mockStream[Req, Res]) doSend(req *Req, err error) {
	m.recv <- mockStreamReq[Req]{data: req, err: err}
}

func (m mockStream[Req, Res]) getSent(t *testing.T) (got *Res) {
	select {
	case got = <-m.sent:
	case <-time.After(timeout):
		require.FailNow(t, "Expected update to have been sent")
	}
	return got
}

func (m mockStream[Req, Res]) syncGetSent(t *testing.T) (got *Res) {
	synctest.Wait()
	select {
	case got = <-m.sent:
	default:
		require.FailNow(t, "Expected update to have been sent")
	}
	return got
}

func (m mockStream[Req, Res]) noGetSent(t *testing.T) {
	select {
	case <-time.After(shortTimeout):
	case <-m.sent:
		require.FailNow(t, "No update should have been sent")
	}
}

func (m mockStream[Req, Res]) Context() context.Context     { return m.ctx }
func (m mockStream[Req, Res]) RecvMsg(any) error            { panic("unimplemented") }
func (m mockStream[Req, Res]) SendHeader(metadata.MD) error { panic("unimplemented") }
func (m mockStream[Req, Res]) SendMsg(any) error            { panic("unimplemented") }
func (m mockStream[Req, Res]) SetHeader(metadata.MD) error  { panic("unimplemented") }
func (m mockStream[Req, Res]) SetTrailer(metadata.MD)       { panic("unimplemented") }

func TestMain(m *testing.M) {
	testutils.GoleakVerifyTestMain(m)
}

func TestServerProbe(t *testing.T) {
	var (
		sloth    = WN{Cluster: "local", Name: "sloth"}
		snail    = WN{Cluster: "local", Name: "snail"}
		apiSloth = &api.Node{Cluster: string(sloth.Cluster), Name: string(sloth.Name)}
		apiSnail = &api.Node{Cluster: string(snail.Cluster), Name: string(snail.Name)}
		timeout  = time.Second
	)

	synctest.Test(t, func(t *testing.T) {
		db, _, actnets, srv := fixture(t)

		var (
			streamSloth = newMockStream[api.ProbeRequest, api.ProbeResponse](t.Context())
			streamSnail = newMockStream[api.ProbeRequest, api.ProbeResponse](t.Context())
		)

		defer func() {
			// Stop all timeout timers.
			close(srv.stop)

			// Force both streams to terminate
			streamSloth.doSend(nil, context.Canceled)
			streamSnail.doSend(nil, context.Canceled)
		}()

		go func() { srv.Probe(streamSloth) }()
		go func() { srv.Probe(streamSnail) }()

		streamSloth.doSend(&api.ProbeRequest{Self: apiSloth, Timeout: durationpb.New(timeout)}, nil)
		streamSnail.doSend(&api.ProbeRequest{Self: apiSnail, Timeout: durationpb.New(timeout)}, nil)

		// A reply should have been received.
		require.Equal(t, &api.ProbeResponse{Status: api.ProbeResponse_SERVING}, streamSloth.syncGetSent(t))
		require.Equal(t, &api.ProbeResponse{Status: api.ProbeResponse_SERVING}, streamSnail.syncGetSent(t))

		// Both nodes should be healthy
		synctest.Wait()
		require.ElementsMatch(t, slices.Collect(maps.Keys(srv.healthy)), []WN{sloth, snail})

		// Pretend that a few networks have been activated.
		wtx := db.WriteTxn(actnets)
		actnets.Insert(wtx, AN{Node: sloth, Network: "green"})
		actnets.Insert(wtx, AN{Node: snail, Network: "yellow"})
		actnets.Insert(wtx, AN{Node: snail, Network: "blue"})
		wtx.Commit()

		// The timeout has not expired, so both nodes should still be healthy.
		time.Sleep(timeout/10*8 - 1*time.Millisecond)
		synctest.Wait()
		require.ElementsMatch(t, slices.Collect(maps.Keys(srv.healthy)), []WN{sloth, snail})

		streamSloth.doSend(&api.ProbeRequest{Self: apiSloth, Timeout: durationpb.New(timeout)}, nil)
		require.Equal(t, &api.ProbeResponse{Status: api.ProbeResponse_SERVING}, streamSloth.syncGetSent(t))
		time.Sleep(1 * time.Millisecond)

		// The snail node should no longer be healthy.
		synctest.Wait()
		require.ElementsMatch(t, slices.Collect(maps.Keys(srv.healthy)), []WN{sloth})

		// The corresponding active network entries should have been dropped.
		require.ElementsMatch(t, statedb.Collect(actnets.All(db.ReadTxn())), []AN{{Node: sloth, Network: "green"}})

		// Healthy again.
		streamSnail.doSend(&api.ProbeRequest{Self: apiSnail, Timeout: durationpb.New(timeout)}, nil)
		require.Equal(t, &api.ProbeResponse{Status: api.ProbeResponse_SERVING}, streamSnail.syncGetSent(t))

		synctest.Wait()
		require.ElementsMatch(t, slices.Collect(maps.Keys(srv.healthy)), []WN{sloth, snail})

		// Break both streams, the nodes should still be healthy until timeout.
		streamSloth.doSend(nil, context.Canceled)
		streamSnail.doSend(nil, context.Canceled)

		time.Sleep(timeout/10*8 - 2*time.Millisecond)

		synctest.Wait()
		require.ElementsMatch(t, slices.Collect(maps.Keys(srv.healthy)), []WN{sloth, snail})

		// Restart only one, and send a new probe.
		go func() { srv.Probe(streamSloth) }()
		streamSloth.doSend(&api.ProbeRequest{Self: apiSloth, Timeout: durationpb.New(timeout)}, nil)
		require.Equal(t, &api.ProbeResponse{Status: api.ProbeResponse_SERVING}, streamSloth.syncGetSent(t))

		// The snail node should no longer be healthy after timeout.
		time.Sleep(10 * time.Millisecond)

		synctest.Wait()
		require.ElementsMatch(t, slices.Collect(maps.Keys(srv.healthy)), []WN{sloth})
	})
}

func TestServerProbeErrors(t *testing.T) {
	var (
		apiSloth = &api.Node{Cluster: "local", Name: "sloth"}
		apiSnail = &api.Node{Cluster: "local", Name: "snail"}
		timeout  = durationpb.New(time.Second)
	)

	tests := []struct {
		name string
		do   func(mockStream[api.ProbeRequest, api.ProbeResponse])
		err  string
	}{
		{
			name: "invalid Self",
			do: func(stream mockStream[api.ProbeRequest, api.ProbeResponse]) {
				stream.doSend(&api.ProbeRequest{Timeout: timeout}, nil)
			},
			err: "invalid [Self] parameter",
		},
		{
			name: "mismatching Self",
			do: func(stream mockStream[api.ProbeRequest, api.ProbeResponse]) {
				stream.doSend(&api.ProbeRequest{Self: apiSloth, Timeout: timeout}, nil)
				stream.doSend(&api.ProbeRequest{Self: apiSnail, Timeout: timeout}, nil)
			},
			err: "mismatching [Self] parameter",
		},
		{
			name: "invalid Timeout",
			do: func(stream mockStream[api.ProbeRequest, api.ProbeResponse]) {
				stream.doSend(&api.ProbeRequest{Self: apiSloth}, nil)
			},
			err: "invalid [Timeout] parameter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				_, _, _, srv := fixture(t)
				defer close(srv.stop)

				var (
					errch  = make(chan error)
					stream = newMockStream[api.ProbeRequest, api.ProbeResponse](t.Context())
				)

				go func() { errch <- srv.Probe(stream) }()

				tt.do(stream)

				err := <-errch
				require.Equal(t, codes.InvalidArgument, status.Code(err))
				require.ErrorContains(t, err, tt.err)
			})
		})
	}

}

func TestServerWatch(t *testing.T) {
	// Ideally, we could use synctest here to not have to depend on timings.
	// However, that turned out not working well because [Table.Changes] makes
	// use of [runtime.SetFinalizer] to unregister the delete tracker. However,
	// finalizers run outside of any bubble [1], causing a fatal error as it
	// eventually closes a channel defined inside the bubble:
	//
	//     fatal error: close of synctest channel from outside bubble
	//
	// [1]: https://pkg.go.dev/testing/synctest#hdr-Isolation
	// > Cleanup functions and finalizers registered with runtime.AddCleanup
	// > and runtime.SetFinalizer run outside of any bubble.

	// Override the settleTime to make the test faster.
	settleTime = 0

	var (
		wg       sync.WaitGroup
		sloth    = WN{Cluster: "local", Name: "sloth"}
		snail    = WN{Cluster: "local", Name: "snail"}
		apiSloth = &api.Node{Cluster: string(sloth.Cluster), Name: string(sloth.Name)}
	)

	db, networks, actnets, srv := fixture(t)

	ctx, cancel := context.WithCancel(t.Context())
	stream := newMockStream[struct{}, api.NetworkEvents](ctx)
	defer func() { cancel(); wg.Wait() }()

	// Configure the initial state.
	wtx := db.WriteTxn(networks, actnets)
	networks.Insert(wtx, PN{Name: "blue", Interface: PNI{Name: "eth.blue", Index: 10}})
	networks.Insert(wtx, PN{Name: "green", Interface: PNI{Name: "eth.green", Index: 11}})
	networks.Insert(wtx, PN{Name: "yellow", Interface: PNI{Name: "eth.yellow", Index: 12}})
	networks.Insert(wtx, PN{Name: "purple", Interface: PNI{Name: "eth.purple", Error: "broken"}})

	actnets.Insert(wtx, AN{Node: sloth, Network: "green"})
	actnets.Insert(wtx, AN{Node: snail, Network: "yellow"})
	actnets.Insert(wtx, AN{Node: snail, Network: "blue"})
	wtx.Commit()

	// Invalid requests should return an InvalidArgument error.
	err := srv.Watch(&api.WatchRequest{}, stream)
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	wg.Go(func() { srv.Watch(&api.WatchRequest{Self: apiSloth}, stream) })

	require.ElementsMatch(t, stream.getSent(t).GetEvents(),
		[]*api.NetworkEvents_Event{
			{Network: &api.Network{Name: "blue"}, Status: api.NetworkEvents_Event_STANDBY},
			{Network: &api.Network{Name: "green"}, Status: api.NetworkEvents_Event_ACTIVE},
			{Network: &api.Network{Name: "yellow"}, Status: api.NetworkEvents_Event_STANDBY},
		},
	)

	// Update the state, and assert that a correct update is sent.
	wtx = db.WriteTxn(networks, actnets)
	networks.Insert(wtx, PN{Name: "red", Interface: PNI{Name: "eth.red", Index: 13}})
	networks.Insert(wtx, PN{Name: "brown", Interface: PNI{Name: "eth.brown", Error: "broken"}})
	networks.Delete(wtx, PN{Name: "blue", Interface: PNI{Name: "eth.blue"}})
	networks.Insert(wtx, PN{Name: "yellow", Interface: PNI{Name: "eth.yellow", Error: "broken"}})
	wtx.Commit()

	require.ElementsMatch(t, stream.getSent(t).GetEvents(),
		[]*api.NetworkEvents_Event{
			{Network: &api.Network{Name: "blue"}, Status: api.NetworkEvents_Event_NOT_SERVING},
			{Network: &api.Network{Name: "brown"}, Status: api.NetworkEvents_Event_NOT_SERVING},
			{Network: &api.Network{Name: "red"}, Status: api.NetworkEvents_Event_STANDBY},
			{Network: &api.Network{Name: "yellow"}, Status: api.NetworkEvents_Event_NOT_SERVING},
		},
	)

	// Update the state again, and assert that a correct update is sent.
	wtx = db.WriteTxn(networks, actnets)
	actnets.Insert(wtx, AN{Node: sloth, Network: "red"})
	actnets.Delete(wtx, AN{Node: sloth, Network: "green"})
	wtx.Commit()

	require.ElementsMatch(t, stream.getSent(t).GetEvents(),
		[]*api.NetworkEvents_Event{
			{Network: &api.Network{Name: "green"}, Status: api.NetworkEvents_Event_STANDBY},
			{Network: &api.Network{Name: "red"}, Status: api.NetworkEvents_Event_ACTIVE},
		},
	)

	// An unrelated update should not trigger an update.
	wtx = db.WriteTxn(networks, actnets)
	actnets.Insert(wtx, AN{Node: snail, Network: "green"})
	wtx.Commit()

	stream.noGetSent(t)
}

func TestServerActivate(t *testing.T) {
	var (
		sloth    = WN{Cluster: "local", Name: "sloth"}
		apiSloth = &api.Node{Cluster: string(sloth.Cluster), Name: string(sloth.Name)}
	)

	db, networks, actnets, srv := fixture(t)

	// Configure the initial state.
	wtx := db.WriteTxn(networks)
	networks.Insert(wtx, PN{Name: "blue", Interface: PNI{Name: "eth.blue", Index: 10}})
	networks.Insert(wtx, PN{Name: "purple", Interface: PNI{Name: "eth.purple", Error: "broken"}})
	wtx.Commit()

	// Pretend that the sloth node is healthy.
	srv.healthy[sloth] = wnEntry{}

	// Invalid requests should return an InvalidArgument error.
	_, err := srv.Activate(t.Context(), &api.ActivationRequest{Network: &api.Network{Name: "yellow"}})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = srv.Activate(t.Context(), &api.ActivationRequest{Self: apiSloth})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	// Activating a network that is unknown should return a FailedPrecondition error.
	_, err = srv.Activate(t.Context(), &api.ActivationRequest{Self: apiSloth, Network: &api.Network{Name: "yellow"}})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	// Activating a network that cannot be served should return a FailedPrecondition error.
	_, err = srv.Activate(t.Context(), &api.ActivationRequest{Self: apiSloth, Network: &api.Network{Name: "purple"}})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	// Activating a network for an unhealthy node should return a FailedPrecondition error.
	other := &api.Node{Cluster: string(sloth.Cluster), Name: "snail"}
	_, err = srv.Activate(t.Context(), &api.ActivationRequest{Self: other, Network: &api.Network{Name: "blue"}})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	// Activating a network that can be served should succeed.
	_, err = srv.Activate(t.Context(), &api.ActivationRequest{Self: apiSloth, Network: &api.Network{Name: "blue"}})
	require.NoError(t, err, "[srv.Activate]")

	// The active networks table should be updated correctly.
	require.ElementsMatch(t, statedb.Collect(actnets.All(db.ReadTxn())), []AN{{Node: sloth, Network: "blue"}})

	// Activating the same network again should succeed.
	_, err = srv.Activate(t.Context(), &api.ActivationRequest{Self: apiSloth, Network: &api.Network{Name: "blue"}})
	require.NoError(t, err, "[srv.Activate]")
}

func TestServerDeactivate(t *testing.T) {
	var (
		sloth    = WN{Cluster: "local", Name: "sloth"}
		apiSloth = &api.Node{Cluster: string(sloth.Cluster), Name: string(sloth.Name)}
	)

	db, networks, actnets, srv := fixture(t)

	// Configure the initial state.
	wtx := db.WriteTxn(networks)
	networks.Insert(wtx, PN{Name: "blue", Interface: PNI{Name: "eth.blue", Index: 10}})
	networks.Insert(wtx, PN{Name: "purple", Interface: PNI{Name: "eth.purple", Error: "broken"}})
	wtx.Commit()

	// Pretend that the sloth node is healthy.
	srv.healthy[sloth] = wnEntry{}

	// Activate one of the networks.
	_, err := srv.Activate(t.Context(), &api.ActivationRequest{Self: apiSloth, Network: &api.Network{Name: "blue"}})
	require.NoError(t, err, "[srv.Activate]")
	require.ElementsMatch(t, statedb.Collect(actnets.All(db.ReadTxn())), []AN{{Node: sloth, Network: "blue"}})

	// Invalid requests should return an InvalidArgument error.
	_, err = srv.Deactivate(t.Context(), &api.DeactivationRequest{Network: &api.Network{Name: "yellow"}})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = srv.Deactivate(t.Context(), &api.DeactivationRequest{Self: apiSloth})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	// Deactivating a network that is unknown should not return an error.
	_, err = srv.Deactivate(t.Context(), &api.DeactivationRequest{Self: apiSloth, Network: &api.Network{Name: "yellow"}})
	require.NoError(t, err, "[srv.Deactivate]")

	// Deactivating a network that cannot be served should not return an error.
	_, err = srv.Deactivate(t.Context(), &api.DeactivationRequest{Self: apiSloth, Network: &api.Network{Name: "purple"}})
	require.NoError(t, err, "[srv.Deactivate]")

	// Deactivating a network for an unhealthy node should not return an error.
	other := &api.Node{Cluster: string(sloth.Cluster), Name: "snail"}
	_, err = srv.Deactivate(t.Context(), &api.DeactivationRequest{Self: other, Network: &api.Network{Name: "blue"}})
	require.NoError(t, err, "[srv.Deactivate]")

	// Deactivating a network that was previously active should succeed.
	_, err = srv.Deactivate(t.Context(), &api.DeactivationRequest{Self: apiSloth, Network: &api.Network{Name: "blue"}})
	require.NoError(t, err, "[srv.Deactivate]")

	// The active networks table should be updated correctly.
	require.Empty(t, statedb.Collect(actnets.All(db.ReadTxn())))

	// Deactivating a network that was already not active should succeed.
	_, err = srv.Deactivate(t.Context(), &api.DeactivationRequest{Self: apiSloth, Network: &api.Network{Name: "blue"}})
	require.NoError(t, err, "[srv.Deactivate]")
}

func TestServerGCer(t *testing.T) {
	// Override the settleTime to make the test faster.
	settleTime = 0

	const interval = 10 * time.Millisecond

	var (
		wg        sync.WaitGroup
		sloth     = WN{Cluster: "local", Name: "sloth"}
		snail     = WN{Cluster: "local", Name: "snail"}
		health, _ = cell.NewSimpleHealth()
	)

	db, networks, actnets, srv := fixture(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); wg.Wait() }()

	// Configure the initial state.
	wtx := db.WriteTxn(networks, actnets)
	networks.Insert(wtx, PN{Name: "blue", Interface: PNI{Name: "eth.blue", Index: 10}})
	networks.Insert(wtx, PN{Name: "green", Interface: PNI{Name: "eth.green", Index: 11}})
	networks.Insert(wtx, PN{Name: "yellow", Interface: PNI{Name: "eth.yellow", Index: 12}})
	networks.Insert(wtx, PN{Name: "purple", Interface: PNI{Name: "eth.purple", Error: "broken"}})

	actnets.Insert(wtx, AN{Node: snail, Network: "blue"})
	actnets.Insert(wtx, AN{Node: sloth, Network: "green"})
	actnets.Insert(wtx, AN{Node: snail, Network: "green"})
	actnets.Insert(wtx, AN{Node: snail, Network: "yellow"})
	actnets.Insert(wtx, AN{Node: snail, Network: "purple"})
	actnets.Insert(wtx, AN{Node: sloth, Network: "purple"})
	wtx.Commit()

	wg.Go(func() { srv.gcLoop(ctx, health) })

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, statedb.Collect(actnets.All(db.ReadTxn())), []AN{
			{Node: snail, Network: "blue"},
			{Node: sloth, Network: "green"},
			{Node: snail, Network: "green"},
			{Node: snail, Network: "yellow"},
		})
	}, timeout, interval)

	// Delete one of the networks, the corresponding entries should be removed.
	wtx = db.WriteTxn(networks)
	networks.Delete(wtx, PN{Name: "green"})
	wtx.Commit()

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, statedb.Collect(actnets.All(db.ReadTxn())), []AN{
			{Node: snail, Network: "blue"},
			{Node: snail, Network: "yellow"},
		})
	}, timeout, interval)

	// One of the networks is no longer served, the corresponding entries should be removed.
	wtx = db.WriteTxn(networks)
	networks.Insert(wtx, PN{Name: "blue", Interface: PNI{Name: "eth.blue", Error: "broken"}})
	wtx.Commit()

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, statedb.Collect(actnets.All(db.ReadTxn())), []AN{
			{Node: snail, Network: "yellow"},
		})
	}, timeout, interval)
}

func TestDefaultListenerFactory(t *testing.T) {
	tests := []struct {
		name      string
		addresses []notypes.Address
		expected  []string
		assertErr assert.ErrorAssertionFunc
	}{
		{
			name: "ipv4-only",
			addresses: []notypes.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.0.1")},
				{Type: addressing.NodeExternalIP, IP: net.ParseIP("10.255.0.1")},
			},
			expected:  []string{"10.0.0.1:1234"},
			assertErr: assert.NoError,
		},
		{
			name: "ipv6-only",
			addresses: []notypes.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("fd10::1")},
				{Type: addressing.NodeExternalIP, IP: net.ParseIP("fc10::1")},
			},
			expected:  []string{"[fd10::1]:1234"},
			assertErr: assert.NoError,
		},
		{
			name: "dual-stack",
			addresses: []notypes.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.0.1")},
				{Type: addressing.NodeExternalIP, IP: net.ParseIP("10.255.0.1")},
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("fd10::1")},
				{Type: addressing.NodeExternalIP, IP: net.ParseIP("fc10::1")},
			},
			expected:  []string{"10.0.0.1:1234", "[fd10::1]:1234"},
			assertErr: assert.NoError,
		},
		{
			name: "fallback",
			addresses: []notypes.Address{
				{Type: addressing.NodeExternalIP, IP: net.ParseIP("10.255.0.1")},
				{Type: addressing.NodeExternalIP, IP: net.ParseIP("fc10::1")},
			},
			expected:  []string{"10.255.0.1:1234", "[fc10::1]:1234"},
			assertErr: assert.NoError,
		},
		{
			name:      "missing",
			assertErr: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				cfg = config.Config{Port: 1234}
				lns = node.NewTestLocalNodeStore(
					node.LocalNode{Node: notypes.Node{IPAddresses: tt.addresses}},
				)

				factory = newDefaultListenerFactory(cfg, lns)
			)

			defer func(orig func(string, string) (net.Listener, error)) { netListen = orig }(netListen)
			netListen = func(network, address string) (net.Listener, error) {
				if network != "tcp" {
					return nil, fmt.Errorf("unexpected network protocol %q", network)
				}

				if !slices.Contains(tt.expected, address) {
					return nil, fmt.Errorf("unexpected address %q", address)
				}

				return &net.TCPListener{}, nil
			}

			// Assert that the local node annotation is correctly set.
			ln, err := lns.Get(t.Context())
			require.NoError(t, err, "[lns.Get]")
			assert.Equal(t, "1234", ln.Annotations[types.PrivateNetworkINBHealthServerPortAnnotation])

			listeners, err := factory(t.Context())
			tt.assertErr(t, err)
			assert.Len(t, listeners, len(tt.expected))
		})
	}
}
