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
	"log/slog"
	"maps"
	"slices"
	"testing"
	"testing/synctest"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	api "github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/api/v1"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/time"
)

type (
	PN  = tables.PrivateNetwork
	PNI = tables.PrivateNetworkInterface
	AN  = tables.ActiveNetwork
	WN  = tables.WorkloadNode
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

func (m mockStream[Req, Res]) syncGetSent(t *testing.T) (got *Res) {
	synctest.Wait()
	select {
	case got = <-m.sent:
	default:
		require.FailNow(t, "Expected update to have been sent")
	}
	return got
}

func (m mockStream[Req, Res]) Context() context.Context     { return m.ctx }
func (m mockStream[Req, Res]) RecvMsg(any) error            { panic("unimplemented") }
func (m mockStream[Req, Res]) SendHeader(metadata.MD) error { panic("unimplemented") }
func (m mockStream[Req, Res]) SendMsg(any) error            { panic("unimplemented") }
func (m mockStream[Req, Res]) SetHeader(metadata.MD) error  { panic("unimplemented") }
func (m mockStream[Req, Res]) SetTrailer(metadata.MD)       { panic("unimplemented") }

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
		time.Sleep(timeout - 1*time.Millisecond)
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

		time.Sleep(timeout - 2*time.Millisecond)

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
		timeout  = time.Second
	)

	tests := []struct {
		name string
		do   func(mockStream[api.ProbeRequest, api.ProbeResponse])
	}{
		{
			name: "invalid Self",
			do: func(stream mockStream[api.ProbeRequest, api.ProbeResponse]) {
				stream.doSend(&api.ProbeRequest{Timeout: durationpb.New(timeout)}, nil)
			},
		},
		{
			name: "mismatching Self",
			do: func(stream mockStream[api.ProbeRequest, api.ProbeResponse]) {
				stream.doSend(&api.ProbeRequest{Self: apiSloth, Timeout: durationpb.New(timeout)}, nil)
				stream.doSend(&api.ProbeRequest{Self: apiSnail, Timeout: durationpb.New(timeout)}, nil)
			},
		},
		{
			name: "invalid Timeout",
			do: func(stream mockStream[api.ProbeRequest, api.ProbeResponse]) {
				stream.doSend(&api.ProbeRequest{Self: apiSloth}, nil)
			},
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
				require.Equal(t, codes.InvalidArgument, status.Code(<-errch))
			})
		})
	}

}
