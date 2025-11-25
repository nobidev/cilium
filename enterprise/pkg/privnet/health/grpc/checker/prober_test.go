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
	"testing"
	"testing/synctest"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/stream"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	api "github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/api/v1"
	"github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/lock"
)

type mockHealthClient struct {
	ctx context.Context

	validator func(*api.ProbeRequest)

	send chan struct{}

	requestCount uint32

	// mu protects the access to the below fields. Strictly speaking, it should
	// not be required thanks to the synctest properties, but apparently the
	// race detector still reports a race, so here it is...
	mu             lock.Mutex
	responseSkip   bool
	responseStatus api.ProbeResponse_ServingStatus
	responseError  error
}

func newMockHealthClient(validator func(*api.ProbeRequest)) *mockHealthClient {
	return &mockHealthClient{
		validator: validator, send: make(chan struct{}, 10), responseStatus: api.ProbeResponse_SERVING,
	}
}

func (m *mockHealthClient) set(skip bool, status api.ProbeResponse_ServingStatus, err error) {
	synctest.Wait()

	m.mu.Lock()
	m.responseSkip = skip
	m.responseStatus = status
	m.responseError = err
	m.mu.Unlock()
}

func (m *mockHealthClient) Probe(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[api.ProbeRequest, api.ProbeResponse], error) {
	m.ctx = ctx
	return m, nil
}

func (m *mockHealthClient) Send(req *api.ProbeRequest) error {
	m.validator(req)
	m.requestCount++
	m.send <- struct{}{}
	return nil
}

func (m *mockHealthClient) Recv() (*api.ProbeResponse, error) {
	for {
		select {
		case <-m.send:
			m.mu.Lock()
			if m.responseSkip {
				m.mu.Unlock()
				continue
			}

			defer m.mu.Unlock()
			return &api.ProbeResponse{Status: m.responseStatus}, m.responseError
		case <-m.ctx.Done():
			return nil, m.ctx.Err()
		}
	}
}

func (m *mockHealthClient) CloseSend() error             { panic("unimplemented") }
func (m *mockHealthClient) Context() context.Context     { return m.ctx }
func (m *mockHealthClient) Header() (metadata.MD, error) { panic("unimplemented") }
func (m *mockHealthClient) RecvMsg(any) error            { panic("unimplemented") }
func (m *mockHealthClient) SendMsg(any) error            { panic("unimplemented") }
func (m *mockHealthClient) Trailer() metadata.MD         { panic("unimplemented") }

type mockHealthClientFailing struct {
	blocked bool
	count   uint
}

func (m *mockHealthClientFailing) Probe(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[api.ProbeRequest, api.ProbeResponse], error) {
	m.count++

	if m.blocked {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	return nil, errors.New("failing on purpose")
}

func TestProber(t *testing.T) {
	var (
		cfg     = config.Config{Interval: 1 * time.Second, Timeout: 2500 * time.Millisecond}
		fixture = func(t *testing.T, ctx context.Context, cl api.HealthClient) <-chan tables.INBNodeState {
			prober := newProber(
				hivetest.Logger(t), cfg, cl,
				&api.Node{Cluster: "foo", Name: "bar"},
			)

			go func() { prober.Run(ctx) }()
			return stream.ToChannel(ctx, prober)
		}

		validator = func(t *testing.T) func(*api.ProbeRequest) {
			return func(req *api.ProbeRequest) {
				require.Equal(t, "foo", req.GetSelf().GetCluster())
				require.Equal(t, "bar", req.GetSelf().GetName())
				require.Equal(t, cfg.Timeout, req.GetTimeout().AsDuration())
			}
		}
	)

	t.Run("persistently-blocked", func(t *testing.T) {
		synctest.Test(t, Wrapped(func(t *testing.T, ctx context.Context) {
			mock := mockHealthClientFailing{blocked: true}
			transitions := fixture(t, ctx, &mock)

			// No transition should be bubbled up until the timeout expires.
			time.Sleep(cfg.Timeout - 1*time.Millisecond)
			NoExpect(t, transitions)

			// Make the timeout expire, should be propagated.
			time.Sleep(2 * time.Millisecond)
			Expect(t, transitions, tables.INBNodeStateUnhealthy)

			require.EqualValues(t, 1, mock.count, "Probe should have been invoked exactly once")
		}))
	})

	t.Run("persistently-failing", func(t *testing.T) {
		synctest.Test(t, Wrapped(func(t *testing.T, ctx context.Context) {
			mock := mockHealthClientFailing{blocked: false}
			transitions := fixture(t, ctx, &mock)

			// Should transition to unhealthy once the timeout expired.
			time.Sleep(cfg.Timeout)
			Expect(t, transitions, tables.INBNodeStateUnhealthy)

			require.EqualValues(t, 3, mock.count, "Probe should have been invoked three times")
		}))
	})

	t.Run("persistently-successful", func(t *testing.T) {
		synctest.Test(t, Wrapped(func(t *testing.T, ctx context.Context) {
			mock := newMockHealthClient(validator(t))
			transitions := fixture(t, ctx, mock)

			// Should immediately transition to healthy.
			Expect(t, transitions, tables.INBNodeStateHealthy)

			require.EqualValues(t, 1, mock.requestCount, "One probe should have been sent")
			for i := range 3 {
				time.Sleep(1 * time.Second)
				synctest.Wait()
				require.EqualValues(t, i+2, mock.requestCount, "One more should have been sent")
			}
		}))
	})

	t.Run("successful-then-denied-then-successful", func(t *testing.T) {
		synctest.Test(t, Wrapped(func(t *testing.T, ctx context.Context) {
			mock := newMockHealthClient(validator(t))
			transitions := fixture(t, ctx, mock)

			// Should immediately transition to healthy.
			Expect(t, transitions, tables.INBNodeStateHealthy)

			// The INB is no longer serving, should transition to unhealthy.
			mock.set(false, api.ProbeResponse_UNKNOWN, nil)
			time.Sleep(1 * time.Second)
			Expect(t, transitions, tables.INBNodeStateUnhealthy)

			// The INB is serving again, should transition to healthy.
			mock.set(false, api.ProbeResponse_SERVING, nil)
			time.Sleep(1 * time.Second)
			Expect(t, transitions, tables.INBNodeStateHealthy)
		}))
	})

	t.Run("successful-then-error-then-successful", func(t *testing.T) {
		synctest.Test(t, Wrapped(func(t *testing.T, ctx context.Context) {
			mock := newMockHealthClient(validator(t))
			transitions := fixture(t, ctx, mock)

			// Should immediately transition to healthy.
			Expect(t, transitions, tables.INBNodeStateHealthy)

			// Recv returns an error, should transition to unhealthy once the
			// timeout expires.
			mock.set(false, api.ProbeResponse_SERVING, errors.New("failing on purpose"))
			time.Sleep(1 * time.Second)
			NoExpect(t, transitions)

			time.Sleep(1500 * time.Millisecond)
			Expect(t, transitions, tables.INBNodeStateUnhealthy)

			// The INB is serving again, should transition to healthy.
			mock.set(false, api.ProbeResponse_SERVING, nil)
			time.Sleep(1 * time.Second)
			Expect(t, transitions, tables.INBNodeStateHealthy)
		}))
	})

	t.Run("successful-then-blocked-multiple-times", func(t *testing.T) {
		synctest.Test(t, Wrapped(func(t *testing.T, ctx context.Context) {
			mock := newMockHealthClient(validator(t))
			transitions := fixture(t, ctx, mock)

			// Should immediately transition to healthy.
			Expect(t, transitions, tables.INBNodeStateHealthy)

			for range 3 {
				// Recv does not return, should transition to unhealthy once the
				// timeout expires.
				mock.set(true, api.ProbeResponse_SERVING, nil)
				time.Sleep(cfg.Timeout)
				Expect(t, transitions, tables.INBNodeStateUnhealthy)

				// The INB is serving again, should transition to healthy.
				mock.set(false, api.ProbeResponse_SERVING, nil)

				// Trigger a response, as we blindly ignored the previous ones. In
				// reality, the probes are sent over a reliable channel, so we are
				// guaranteed to eventually either receive a response or an error.
				mock.send <- struct{}{}
				Expect(t, transitions, tables.INBNodeStateHealthy)
			}
		}))
	})
}
