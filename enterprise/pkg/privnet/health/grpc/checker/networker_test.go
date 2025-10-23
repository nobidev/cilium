//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package checker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/stream"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	api "github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/api/v1"
	"github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

type mockNetworksClient struct {
	ctx context.Context

	events chan response[*api.NetworkEvents]

	actRequest  chan request
	actResponse chan response[*api.ActivationResponse]

	deactRequest  chan request
	deactResponse chan response[*api.DeactivationResponse]
}

type request interface {
	GetSelf() *api.Node
	GetNetwork() *api.Network
}

type response[T any] struct {
	data T
	err  error
}

func newResponse[T any](data T, err error) response[T] {
	return response[T]{data: data, err: err}
}

func (m response[T]) out() (T, error) {
	return m.data, m.err
}

func newMockNetworksClient() *mockNetworksClient {
	return &mockNetworksClient{
		events:        make(chan response[*api.NetworkEvents]),
		actRequest:    make(chan request),
		actResponse:   make(chan response[*api.ActivationResponse]),
		deactRequest:  make(chan request),
		deactResponse: make(chan response[*api.DeactivationResponse]),
	}
}

// Activate implements api.NetworksClient.
func (m *mockNetworksClient) Activate(ctx context.Context, in *api.ActivationRequest, opts ...grpc.CallOption) (*api.ActivationResponse, error) {
	select {
	case m.actRequest <- in:
		return (<-m.actResponse).out()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Deactivate implements api.NetworksClient.
func (m *mockNetworksClient) Deactivate(ctx context.Context, in *api.DeactivationRequest, opts ...grpc.CallOption) (*api.DeactivationResponse, error) {
	select {
	case m.deactRequest <- in:
		return (<-m.deactResponse).out()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Watch implements api.NetworksClient.
func (m *mockNetworksClient) Watch(ctx context.Context, in *api.WatchRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[api.NetworkEvents], error) {
	m.ctx = ctx
	return m, nil
}

func (m *mockNetworksClient) Recv() (*api.NetworkEvents, error) {
	for {
		select {
		case event := <-m.events:
			return event.out()
		case <-m.ctx.Done():
			return nil, m.ctx.Err()
		}
	}
}

func (m *mockNetworksClient) CloseSend() error             { panic("unimplemented") }
func (m *mockNetworksClient) Context() context.Context     { return m.ctx }
func (m *mockNetworksClient) Header() (metadata.MD, error) { panic("unimplemented") }
func (m *mockNetworksClient) RecvMsg(any) error            { panic("unimplemented") }
func (m *mockNetworksClient) SendMsg(any) error            { panic("unimplemented") }
func (m *mockNetworksClient) Trailer() metadata.MD         { panic("unimplemented") }

func TestNetworker(t *testing.T) {
	const (
		C = tables.INBNetworkStateConfirmed
		D = tables.INBNetworkStateDenied
		U = tables.INBNetworkStateUnknown
	)

	synctest.Test(t, Wrapped(func(t *testing.T, ctx context.Context) {
		var (
			cctx, cancel = context.WithCancel(ctx)
			wg           sync.WaitGroup

			self = api.Node{Cluster: "foo", Name: "bar"}
			mock = newMockNetworksClient()

			cfg       = config.Config{Interval: 1 * time.Second, Timeout: 2500 * time.Millisecond}
			networker = newNetworker(hivetest.Logger(t), cfg, mock, &self)

			// The transitions channel is buffered so that [Register] and [Deregister]
			// operations are not blocking, for convenience.
			transitions = stream.ToChannel(ctx, networker, stream.WithBufferSize(10))
		)

		defer func() {
			cancel()
			wg.Wait()
		}()

		wg.Go(func() { networker.Run(cctx) })

		// Register a few networks.
		networker.Register("catfish")
		networker.Register("pelican")
		networker.Register("shrimp")
		networker.Register("terrapin")

		Expect(t, transitions, networkTransition{network: "catfish", state: U})
		Expect(t, transitions, networkTransition{network: "pelican", state: U})
		Expect(t, transitions, networkTransition{network: "shrimp", state: U})
		Expect(t, transitions, networkTransition{network: "terrapin", state: U})

		// Observe the initial snapshot of events, and assert that transitions are emitted.
		mock.events <- newResponse(&api.NetworkEvents{Events: []*api.NetworkEvents_Event{
			{Network: &api.Network{Name: "pelican"}, Status: api.NetworkEvents_Event_STANDBY},
			{Network: &api.Network{Name: "bonefish"}, Status: api.NetworkEvents_Event_STANDBY},
			{Network: &api.Network{Name: "catfish"}, Status: api.NetworkEvents_Event_STANDBY},
			{Network: &api.Network{Name: "shrimp"}, Status: api.NetworkEvents_Event_NOT_SERVING},
		}}, nil)

		Expect(t, transitions, networkTransition{network: "pelican", state: C})  // Explicitly confirmed
		Expect(t, transitions, networkTransition{network: "catfish", state: C})  // Explicitly confirmed
		Expect(t, transitions, networkTransition{network: "shrimp", state: D})   // Explicitly denied
		Expect(t, transitions, networkTransition{network: "terrapin", state: D}) // Not seen
		Expect(t, transitions, networkTransitionSync)

		// Register a few other networks, and assert that events are emitted.
		networker.Register("hamster")
		networker.Register("bonefish")

		Expect(t, transitions, networkTransition{network: "hamster", state: D})  // Not seen
		Expect(t, transitions, networkTransition{network: "bonefish", state: C}) // Explicitly confirmed

		// Observe incremental changes, and assert that transitions are emitted.
		mock.events <- newResponse(&api.NetworkEvents{Events: []*api.NetworkEvents_Event{
			{Network: &api.Network{Name: "hamster"}, Status: api.NetworkEvents_Event_STANDBY},
			{Network: &api.Network{Name: "bonefish"}, Status: api.NetworkEvents_Event_NOT_SERVING},
		}}, nil)

		Expect(t, transitions, networkTransition{network: "hamster", state: C})  // Explicitly confirmed
		Expect(t, transitions, networkTransition{network: "bonefish", state: D}) // Explicitly denied

		// Register/deregister a few more networks, and assert that events are emitted.
		networker.Register("hamster") // Already registered, no event should be emitted

		require.True(t, networker.Deregister("bonefish"), "[Deregister]") // Was denied
		require.True(t, networker.Deregister("pelican"), "[Deregister]")  // Was confirmed

		// Observe transitions again, and assert that the initial state is replayed.
		// Order is not guaranteed when relaying the transitions.
		secondary := stream.ToChannel(cctx, networker, stream.WithBufferSize(10))
		Expect(t, secondary,
			networkTransition{network: "catfish", state: C},
			networkTransition{network: "hamster", state: C},
			networkTransition{network: "shrimp", state: D},
			networkTransition{network: "terrapin", state: D},
		)
		Expect(t, secondary, networkTransitionSync)

		networker.Register("pelican")
		networker.Register("bonefish")

		Expect(t, transitions, networkTransition{network: "pelican", state: C})
		Expect(t, transitions, networkTransition{network: "bonefish", state: D})

		Expect(t, secondary, networkTransition{network: "pelican", state: C})
		Expect(t, secondary, networkTransition{network: "bonefish", state: D})

		// Stop the watcher (and the secondary observer).
		cancel()
		wg.Wait()

		// Trigger a reset, and observe that events are emitted.
		networker.ResetToUnknown()

		// Order is not deterministic, given that entries are extracted from a map.
		Expect(t, transitions,
			networkTransition{network: "bonefish", state: U},
			networkTransition{network: "catfish", state: U},
			networkTransition{network: "hamster", state: U},
			networkTransition{network: "pelican", state: U},
			networkTransition{network: "shrimp", state: U},
			networkTransition{network: "terrapin", state: U},
		)

		// Register/deregister a few more networks, and assert that events are emitted correctly.
		require.True(t, networker.Deregister("shrimp"), "[Deregister]")
		require.True(t, networker.Deregister("catfish"), "[Deregister]")
		networker.Register("catfish")
		networker.Register("hound")

		Expect(t, transitions, networkTransition{network: "catfish", state: U})
		Expect(t, transitions, networkTransition{network: "hound", state: U})

		// Trigger a reset again, and observe that events are emitted.
		networker.ResetToUnknown()

		// Order is not deterministic, given that entries are extracted from a map.
		Expect(t, transitions,
			networkTransition{network: "bonefish", state: U},
			networkTransition{network: "catfish", state: U},
			networkTransition{network: "hamster", state: U},
			networkTransition{network: "hound", state: U},
			networkTransition{network: "pelican", state: U},
			networkTransition{network: "terrapin", state: U},
		)

		cctx, cancel = context.WithCancel(ctx)
		defer cancel()
		wg.Go(func() { networker.Run(cctx) })

		// Observe the initial snapshot of events, and assert that transitions are emitted again.
		mock.events <- newResponse(&api.NetworkEvents{Events: []*api.NetworkEvents_Event{
			{Network: &api.Network{Name: "catfish"}, Status: api.NetworkEvents_Event_STANDBY},
			{Network: &api.Network{Name: "shrimp"}, Status: api.NetworkEvents_Event_STANDBY},
			{Network: &api.Network{Name: "hamster"}, Status: api.NetworkEvents_Event_STANDBY},
		}}, nil)

		Expect(t, transitions, networkTransition{network: "catfish", state: C})
		Expect(t, transitions, networkTransition{network: "hamster", state: C})

		// Order is not deterministic.
		Expect(t, transitions,
			networkTransition{network: "bonefish", state: D},
			networkTransition{network: "hound", state: D},
			networkTransition{network: "pelican", state: D},
			networkTransition{network: "terrapin", state: D},
		)

		// Break the watch channel, should correctly update the networks based on the new snapshot.
		mock.events <- newResponse[*api.NetworkEvents](nil, errors.New("failing on purpose"))
		mock.events <- newResponse(&api.NetworkEvents{Events: []*api.NetworkEvents_Event{
			{Network: &api.Network{Name: "hamster"}, Status: api.NetworkEvents_Event_STANDBY},
			{Network: &api.Network{Name: "hound"}, Status: api.NetworkEvents_Event_STANDBY},
			{Network: &api.Network{Name: "shrimp"}, Status: api.NetworkEvents_Event_STANDBY},
		}}, nil)

		Expect(t, transitions, networkTransition{network: "hound", state: C})
		Expect(t, transitions, networkTransition{network: "catfish", state: D})

		// Deregister all remaining networks
		require.True(t, networker.Deregister("bonefish"), "[Deregister]")
		require.True(t, networker.Deregister("catfish"), "[Deregister]")
		require.True(t, networker.Deregister("hamster"), "[Deregister]")
		require.True(t, networker.Deregister("hound"), "[Deregister]")
		require.True(t, networker.Deregister("pelican"), "[Deregister]")
		require.False(t, networker.Deregister("terrapin"), "[Deregister]")

		select {
		case tr := <-transitions:
			require.FailNow(t, "Observed unexpected transition", "transition: %+v", tr)
		default:
		}
	}))
}

func TestNetworkerActivate(t *testing.T) {
	const (
		C = tables.INBNetworkStateConfirmed
		D = tables.INBNetworkStateDenied
		U = tables.INBNetworkStateUnknown
	)

	synctest.Test(t, Wrapped(func(t *testing.T, ctx context.Context) {
		var (
			cctx, cancel = context.WithCancel(ctx)
			wg           sync.WaitGroup

			self = api.Node{Cluster: "foo", Name: "bar"}
			mock = newMockNetworksClient()

			cfg       = config.Config{Interval: 1 * time.Second, Timeout: 2500 * time.Millisecond}
			networker = newNetworker(hivetest.Logger(t), cfg, mock, &self)

			// The transitions channel is buffered so that [Register] and [Deregister]
			// operations are not blocking, for convenience.
			transitions = stream.ToChannel(ctx, networker, stream.WithBufferSize(10))
		)

		defer func() {
			cancel()
			wg.Wait()
		}()

		wg.Go(func() { networker.Run(cctx) })

		// Register a few networks.
		networker.Register("catfish")
		networker.Register("hamster")
		networker.Register("pelican")
		networker.Register("shrimp")

		Expect(t, transitions, networkTransition{network: "catfish", state: U})
		Expect(t, transitions, networkTransition{network: "hamster", state: U})
		Expect(t, transitions, networkTransition{network: "pelican", state: U})
		Expect(t, transitions, networkTransition{network: "shrimp", state: U})

		mock.events <- newResponse(&api.NetworkEvents{Events: []*api.NetworkEvents_Event{
			{Network: &api.Network{Name: "catfish"}, Status: api.NetworkEvents_Event_STANDBY},
			{Network: &api.Network{Name: "hamster"}, Status: api.NetworkEvents_Event_STANDBY},
			{Network: &api.Network{Name: "pelican"}, Status: api.NetworkEvents_Event_STANDBY},
		}}, nil)

		Expect(t, transitions, networkTransition{network: "catfish", state: C})
		Expect(t, transitions, networkTransition{network: "hamster", state: C})
		Expect(t, transitions, networkTransition{network: "pelican", state: C})
		Expect(t, transitions, networkTransition{network: "shrimp", state: D})
		Expect(t, transitions, networkTransitionSync)

		// Activate two networks.
		require.NoError(t, networker.Activate("catfish"), "[Activate]")
		require.NoError(t, networker.Activate("hamster"), "[Activate]")

		activation := Get(t, mock.actRequest)
		require.Equal(t, &self, activation.GetSelf())
		require.Equal(t, "catfish", activation.GetNetwork().GetName())
		mock.actResponse <- newResponse(&api.ActivationResponse{}, nil)

		activation = Get(t, mock.actRequest)
		require.Equal(t, &self, activation.GetSelf())
		require.Equal(t, "hamster", activation.GetNetwork().GetName())
		mock.actResponse <- newResponse(&api.ActivationResponse{}, nil)

		// None of the following should trigger an activation.
		require.NoError(t, networker.Activate("catfish"), "[Activate]") // Already active
		require.Error(t, networker.Activate("bonefish"), "[Activate]")  // Not registered
		require.Error(t, networker.Activate("shrimp"), "[Activate]")    // Denied

		require.NoError(t, networker.Activate("pelican"), "[Activate]")

		activation = Get(t, mock.actRequest)
		require.Equal(t, &self, activation.GetSelf())
		require.Equal(t, "pelican", activation.GetNetwork().GetName())

		// The activation request is denied, hence the network should transition to denied state.
		mock.actResponse <- newResponse(&api.ActivationResponse{}, status.Error(codes.FailedPrecondition, "on purpose"))
		Expect(t, transitions, networkTransition{network: "pelican", state: D})

		// Send an incremental update. It should have no effect for catfish, as it matches
		// the expected state, while it should trigger a new activation for hamster.
		mock.events <- newResponse(&api.NetworkEvents{Events: []*api.NetworkEvents_Event{
			{Network: &api.Network{Name: "catfish"}, Status: api.NetworkEvents_Event_ACTIVE},
			{Network: &api.Network{Name: "hamster"}, Status: api.NetworkEvents_Event_STANDBY},
		}}, nil)

		activation = Get(t, mock.actRequest)
		require.Equal(t, &self, activation.GetSelf())
		require.Equal(t, "hamster", activation.GetNetwork().GetName())
		mock.actResponse <- newResponse(&api.ActivationResponse{}, nil)

		// Deregister a network, should trigger a deactivation
		networker.Deregister("hamster")

		deactivation := Get(t, mock.deactRequest)
		require.Equal(t, &self, deactivation.GetSelf())
		require.Equal(t, "hamster", deactivation.GetNetwork().GetName())
		mock.deactResponse <- newResponse(&api.DeactivationResponse{}, nil)

		require.ElementsMatch(t, []tables.NetworkName{"catfish"}, networker.active())

		// Break the watch channel, should replay the activations after sync.
		mock.events <- newResponse[*api.NetworkEvents](nil, errors.New("failing on purpose"))
		mock.events <- newResponse(&api.NetworkEvents{Events: []*api.NetworkEvents_Event{
			{Network: &api.Network{Name: "catfish"}, Status: api.NetworkEvents_Event_STANDBY},
			{Network: &api.Network{Name: "hamster"}, Status: api.NetworkEvents_Event_STANDBY},
		}}, nil)

		activation = Get(t, mock.actRequest)
		require.Equal(t, &self, activation.GetSelf())
		require.Equal(t, "catfish", activation.GetNetwork().GetName())
		mock.actResponse <- newResponse(&api.ActivationResponse{}, nil)

		// None of the following should trigger a deactivation.
		require.Error(t, networker.Deactivate("hamster"), "[Deactivate]")   // Not registered
		require.NoError(t, networker.Deactivate("pelican"), "[Deactivate]") // Denied

		require.NoError(t, networker.Deactivate("catfish"), "[Deactivate]")

		deactivation = Get(t, mock.deactRequest)
		require.Equal(t, &self, deactivation.GetSelf())
		require.Equal(t, "catfish", deactivation.GetNetwork().GetName())
		mock.deactResponse <- newResponse(&api.DeactivationResponse{}, nil)
		require.Empty(t, networker.active())

		// Activate again a few networks
		networker.Register("hamster")
		Expect(t, transitions, networkTransition{network: "hamster", state: C})

		require.NoError(t, networker.Activate("hamster"), "[Activate]")
		require.NoError(t, networker.Activate("catfish"), "[Activate]")

		activation = Get(t, mock.actRequest)
		require.Equal(t, "hamster", activation.GetNetwork().GetName())
		mock.actResponse <- newResponse(&api.ActivationResponse{}, nil)
		activation = Get(t, mock.actRequest)
		require.Equal(t, "catfish", activation.GetNetwork().GetName())
		mock.actResponse <- newResponse(&api.ActivationResponse{}, nil)

		// The INB reports two standby networks as active (one registered, the other not), which should
		// trigger the corresponding deactivations.
		mock.events <- newResponse(&api.NetworkEvents{Events: []*api.NetworkEvents_Event{
			{Network: &api.Network{Name: "pelican"}, Status: api.NetworkEvents_Event_ACTIVE},
			{Network: &api.Network{Name: "beetle"}, Status: api.NetworkEvents_Event_ACTIVE},
		}}, nil)

		Expect(t, transitions, networkTransition{network: "pelican", state: C})

		deactivation = Get(t, mock.deactRequest)
		require.Equal(t, &self, deactivation.GetSelf())
		require.Equal(t, "pelican", deactivation.GetNetwork().GetName())
		mock.deactResponse <- newResponse(&api.DeactivationResponse{}, nil)

		deactivation = Get(t, mock.deactRequest)
		require.Equal(t, &self, deactivation.GetSelf())
		require.Equal(t, "beetle", deactivation.GetNetwork().GetName())
		mock.deactResponse <- newResponse(&api.DeactivationResponse{}, nil)

		// The INB is no longer willing to serve a previously active network.
		mock.events <- newResponse(&api.NetworkEvents{Events: []*api.NetworkEvents_Event{
			{Network: &api.Network{Name: "catfish"}, Status: api.NetworkEvents_Event_NOT_SERVING},
		}}, nil)
		Expect(t, transitions, networkTransition{network: "catfish", state: D})
		require.ElementsMatch(t, []tables.NetworkName{"hamster"}, networker.active())

		// Stop the watcher, none of the networks should be active anymore.
		cancel()
		wg.Wait()

		networker.ResetToUnknown()
		Expect(t, transitions,
			networkTransition{network: "catfish", state: U},
			networkTransition{network: "hamster", state: U},
			networkTransition{network: "pelican", state: U},
			networkTransition{network: "shrimp", state: U},
		)

		require.Empty(t, networker.active())

		select {
		case tr := <-transitions:
			require.FailNow(t, "Observed unexpected transition", "transition: %+v", tr)
		default:
		}
	}))
}

func TestNetworkerActivateRetry(t *testing.T) {
	const (
		C = tables.INBNetworkStateConfirmed
		D = tables.INBNetworkStateDenied
		U = tables.INBNetworkStateUnknown
	)

	type setupFn func(*testing.T, *mockNetworksClient, *networker)

	var (
		cfg  = config.Config{Interval: 1 * time.Second, Timeout: 2500 * time.Millisecond}
		self = api.Node{Cluster: "foo", Name: "bar"}

		fixture = func(t *testing.T, ctx context.Context, extra setupFn) (*mockNetworksClient, *networker, <-chan networkTransition) {
			var (
				mock        = newMockNetworksClient()
				networker   = newNetworker(hivetest.Logger(t), cfg, mock, &self)
				transitions = stream.ToChannel(t.Context(), networker, stream.WithBufferSize(10))
			)

			go func() { networker.Run(ctx) }()

			networker.Register("catfish")
			networker.Register("hamster")

			Expect(t, transitions, networkTransition{network: "catfish", state: U})
			Expect(t, transitions, networkTransition{network: "hamster", state: U})

			mock.events <- newResponse(&api.NetworkEvents{Events: []*api.NetworkEvents_Event{
				{Network: &api.Network{Name: "catfish"}, Status: api.NetworkEvents_Event_STANDBY},
				{Network: &api.Network{Name: "hamster"}, Status: api.NetworkEvents_Event_STANDBY},
			}}, nil)

			Expect(t, transitions, networkTransition{network: "catfish", state: C})
			Expect(t, transitions, networkTransition{network: "hamster", state: C})
			Expect(t, transitions, networkTransitionSync)

			extra(t, mock, networker)
			return mock, networker, transitions
		}
	)

	for _, tt := range []struct {
		prefix string
		fn     func(*networker, tables.NetworkName) error
		setup  setupFn

		reqch   func(m *mockNetworksClient) <-chan request
		respond func(m *mockNetworksClient, err error)
	}{
		{
			prefix: "activate",
			fn:     (*networker).Activate,
			setup:  func(t *testing.T, mnc *mockNetworksClient, n *networker) {},

			reqch: func(m *mockNetworksClient) <-chan request { return m.actRequest },
			respond: func(m *mockNetworksClient, err error) {
				m.actResponse <- newResponse(&api.ActivationResponse{}, err)
			},
		},
		{
			prefix: "deactivate",
			fn:     (*networker).Deactivate,
			setup: func(t *testing.T, mock *mockNetworksClient, networker *networker) {
				for _, net := range []tables.NetworkName{"catfish", "hamster"} {
					require.NoError(t, networker.Activate(net))
					activation := Get(t, mock.actRequest)
					require.Equal(t, string(net), activation.GetNetwork().GetName())
					mock.actResponse <- newResponse(&api.ActivationResponse{}, nil)
				}
			},

			reqch: func(m *mockNetworksClient) <-chan request { return m.deactRequest },
			respond: func(m *mockNetworksClient, err error) {
				m.deactResponse <- newResponse(&api.DeactivationResponse{}, err)
			},
		},
	} {
		t.Run(tt.prefix+"-single-failure", func(t *testing.T) {
			synctest.Test(t, Wrapped(func(t *testing.T, ctx context.Context) {
				mock, networker, _ := fixture(t, ctx, tt.setup)

				require.NoError(t, tt.fn(networker, "catfish"))
				require.NoError(t, tt.fn(networker, "hamster"))

				request := Get(t, tt.reqch(mock))
				require.Equal(t, "catfish", request.GetNetwork().GetName())
				tt.respond(mock, errors.New("failing on purpose"))

				request = Get(t, tt.reqch(mock))
				require.Equal(t, "hamster", request.GetNetwork().GetName())
				tt.respond(mock, nil)

				NoExpect(t, tt.reqch(mock))

				// The request should be eventually retried
				time.Sleep(cfg.Interval)
				request = Get(t, tt.reqch(mock))
				require.Equal(t, "catfish", request.GetNetwork().GetName())
				tt.respond(mock, nil)
			}))
		})

		t.Run(tt.prefix+"-persistent-failure", func(t *testing.T) {
			synctest.Test(t, Wrapped(func(t *testing.T, ctx context.Context) {
				mock, networker, transitions := fixture(t, ctx, tt.setup)
				require.NoError(t, tt.fn(networker, "catfish"))

				for range 2 {
					activation := Get(t, tt.reqch(mock))
					require.Equal(t, "catfish", activation.GetNetwork().GetName())
					tt.respond(mock, errors.New("failing on purpose"))

					time.Sleep(cfg.Interval)
				}

				// No transition should have been emitted yet.
				NoExpect(t, transitions)

				// Third failure, the network should be now marked as denied.
				request := Get(t, tt.reqch(mock))
				require.Equal(t, "catfish", request.GetNetwork().GetName())
				tt.respond(mock, errors.New("failing on purpose"))

				Expect(t, transitions, networkTransition{network: "catfish", state: D})
			}))
		})

		t.Run(tt.prefix+"-timeout", func(t *testing.T) {
			synctest.Test(t, Wrapped(func(t *testing.T, ctx context.Context) {
				_, networker, transitions := fixture(t, ctx, tt.setup)
				require.NoError(t, tt.fn(networker, "catfish"))

				// Two failures due to a timeout.
				time.Sleep(cfg.Timeout + cfg.Interval)
				time.Sleep(cfg.Timeout + cfg.Interval)

				// No transition should have been emitted yet.
				NoExpect(t, transitions)

				// Third failure, the network should be now marked as denied.
				time.Sleep(cfg.Timeout)
				Expect(t, transitions, networkTransition{network: "catfish", state: D})
			}))
		})
	}
}

func TestNetworkerRunInvariants(t *testing.T) {
	synctest.Test(t, Wrapped(func(t *testing.T, ctx context.Context) {
		var (
			cctx, cancel = context.WithCancel(ctx)
			wg           sync.WaitGroup

			self = api.Node{Cluster: "foo", Name: "bar"}
			mock = newMockNetworksClient()

			cfg       = config.Config{Interval: 1 * time.Second, Timeout: 2500 * time.Millisecond}
			networker = newNetworker(hivetest.Logger(t), cfg, mock, &self)

			transitions = stream.ToChannel(ctx, networker)
		)

		wg.Go(func() { networker.Run(cctx) })

		// Make sure that networker is actually running.
		mock.events <- newResponse(&api.NetworkEvents{}, nil)
		Expect(t, transitions, networkTransitionSync)

		require.Panics(t, func() { networker.Run(cctx) }, "Cannot invoke [Run] when already running")
		require.Panics(t, networker.ResetToUnknown, "Cannot invoke [ResetToUnknown] when running")

		cancel()
		wg.Wait()

		require.Panics(t, func() { networker.Run(ctx) },
			"Cannot invoke Run again without calling [ResetToUnknown] first")
	}))
}
