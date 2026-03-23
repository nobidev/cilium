// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package timescape

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	tsv1alphapb "github.com/isovalent/hubble-timescape/api/timescape/v1alpha"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

func TestExporterRunReturnsOnCancelWithBufferedFlows(t *testing.T) {
	backoff := newSignalingBackoff()
	t.Cleanup(backoff.unblock)

	// Reserve a local address, then close it so the exporter stays disconnected
	// and any exported flows remain buffered until shutdown.
	target := reserveTarget(t)
	exporter := newTestExporter(
		t,
		target,
		WithBackoff(backoff),
		WithMaxBufferSize(4),
	)

	cancel, errCh := runExporter(t, exporter)

	// Wait until the exporter is blocked in reconnect backoff before queuing
	// flows.
	require.Equal(t, 1, requireReceive(t, backoff.called, "exporter never entered retry backoff"))
	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(1)))
	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(2)))

	// Before the drain fix, canceling here would hang in Run after consuming the
	// buffered flows because the exporter never closes its buffer channel.
	cancel()
	backoff.unblock()

	requireRunResult(t, errCh, context.Canceled)
	require.Empty(t, exporter.buffer)
}

func TestExporterDropsFlowsWhenBufferFull(t *testing.T) {
	exporter := newTestExporter(
		t,
		"passthrough:///unused",
		WithMaxBufferSize(1),
	)

	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(1)))
	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(2)))

	require.Len(t, exporter.buffer, 1)
	require.EqualValues(t, 1, exporter.droppedFlows.Load())
}

func TestExporterReconnectsAndResetsRetriesAfterSuccessfulSend(t *testing.T) {
	backoff := newSignalingBackoff()
	t.Cleanup(backoff.unblock)

	// Reserve a local address, then close it so the exporter's first connection
	// attempt fails with connection refused on a predictable target.
	target := reserveTarget(t)

	started := make(chan struct{})
	service := &testIngesterService{}
	service.onIngest = func(_ int, stream grpc.ClientStreamingServer[tsv1alphapb.IngestRequest, tsv1alphapb.IngestResponse]) error {
		close(started)
		return service.receiveAll(stream)
	}

	exporter := newTestExporter(
		t,
		target,
		WithBackoff(backoff),
	)

	cancel, errCh := runExporter(t, exporter)

	// Wait until the exporter has observed the failed dial and entered its retry
	// backoff path before starting the server.
	require.Equal(t, 1, requireReceive(t, backoff.called, "exporter never entered retry backoff"))

	// Bring the ingester up on the same target and release the blocked backoff so
	// the next connection attempt can succeed.
	startIngesterServer(t, service, target)
	backoff.unblock()

	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(1)))
	require.NoError(t, exporter.Export(t.Context(), newFlowEvent(2)))
	requireClosed(t, started, "exporter never reconnected")

	// The successful send on the reconnected stream should reset the retry
	// counter back to zero.
	require.Eventually(t, func() bool {
		return slices.Equal(service.nodeNames(), []string{"flow-1", "flow-2"})
	}, time.Second, 10*time.Millisecond)

	cancel()
	requireRunResult(t, errCh, context.Canceled)
	require.Zero(t, exporter.connectRetries)
}

type testIngesterService struct {
	tsv1alphapb.UnimplementedIngesterServiceServer

	mu          lock.Mutex
	streamCount int
	received    []*flowpb.Flow

	onIngest func(int, grpc.ClientStreamingServer[tsv1alphapb.IngestRequest, tsv1alphapb.IngestResponse]) error
}

func (s *testIngesterService) Ingest(stream grpc.ClientStreamingServer[tsv1alphapb.IngestRequest, tsv1alphapb.IngestResponse]) error {
	s.mu.Lock()
	s.streamCount++
	streamNum := s.streamCount
	s.mu.Unlock()

	if s.onIngest != nil {
		return s.onIngest(streamNum, stream)
	}

	return s.receiveAll(stream)
}

func (s *testIngesterService) receiveAll(stream grpc.ClientStreamingServer[tsv1alphapb.IngestRequest, tsv1alphapb.IngestResponse]) error {
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&tsv1alphapb.IngestResponse{})
		}
		if err != nil {
			return err
		}
		if flow := req.GetFlow(); flow != nil {
			s.recordFlow(flow)
		}
	}
}

func (s *testIngesterService) recordFlow(flow *flowpb.Flow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.received = append(s.received, flow)
}

func (s *testIngesterService) nodeNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	names := make([]string, 0, len(s.received))
	for _, flow := range s.received {
		names = append(names, flow.GetNodeName())
	}
	return names
}

func startIngesterServer(t *testing.T, service *testIngesterService, target string) {
	t.Helper()

	listener, err := net.Listen("tcp", target)
	require.NoError(t, err)

	server := grpc.NewServer()
	tsv1alphapb.RegisterIngesterServiceServer(server, service)

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()

	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
		if err := <-errCh; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("ingester server exited with error: %v", err)
		}
	})
}

func newTestExporter(t *testing.T, target string, opts ...Option) *Exporter {
	t.Helper()

	baseOpts := []Option{
		WithReportDroppedFlowsInterval(0),
	}

	exporter, err := NewExporter(
		hivetest.Logger(t),
		target,
		append(baseOpts, opts...)...,
	)
	require.NoError(t, err)

	return exporter
}

func reserveTarget(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	target := listener.Addr().String()
	require.NoError(t, listener.Close())
	return target
}

func runExporter(t *testing.T, exporter *Exporter) (context.CancelFunc, <-chan error) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)
	go func() {
		errCh <- exporter.Run(ctx)
	}()
	return cancel, errCh
}

type signalingBackoff struct {
	called      chan int
	release     chan struct{}
	releaseOnce sync.Once
}

func newSignalingBackoff() *signalingBackoff {
	return &signalingBackoff{
		called:  make(chan int, 1),
		release: make(chan struct{}),
	}
}

func (b *signalingBackoff) Duration(attempt int) time.Duration {
	select {
	case b.called <- attempt:
	default:
	}

	<-b.release
	return 0
}

func (b *signalingBackoff) unblock() {
	b.releaseOnce.Do(func() {
		close(b.release)
	})
}

func requireClosed(t *testing.T, ch <-chan struct{}, msg string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal(msg)
	}
}

func requireRunResult(t *testing.T, errCh <-chan error, want error) {
	t.Helper()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, want)
	case <-time.After(2 * time.Second):
		t.Fatalf("exporter did not stop within timeout, want %v", want)
	}
}

func requireReceive[T any](t *testing.T, ch <-chan T, msg string) T {
	t.Helper()

	select {
	case value := <-ch:
		return value
	case <-time.After(2 * time.Second):
		t.Fatal(msg)
	}

	var zero T
	return zero
}

func newFlowEvent(id int) *v1.Event {
	return &v1.Event{
		Event: &flowpb.Flow{
			NodeName: fmt.Sprintf("flow-%d", id),
			Time:     timestamppb.New(time.Unix(int64(id), 0)),
		},
	}
}
