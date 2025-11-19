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
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	tsv1alphapb "github.com/isovalent/hubble-timescape/api/timescape/v1alpha"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/dial"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/exporter"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// OnExportEvent is a hook that can be registered on a timescape exporter and is invoked for each
// event.
//
// Returning false will stop the export pipeline for the current event, meaning the default export
// logic as well as the following hooks will not run.
type OnExportEvent interface {
	OnExportEvent(ctx context.Context, ev *v1.Event) (stop bool, err error)
}

// OnExportEventFunc implements OnExportEvent for a single function.
type OnExportEventFunc func(ctx context.Context, ev *v1.Event) (stop bool, err error)

// OnExportEvent implements OnExportEvent.
func (f OnExportEventFunc) OnExportEvent(ctx context.Context, ev *v1.Event) (bool, error) {
	return f(ctx, ev)
}

var _ exporter.FlowLogExporter = (*Exporter)(nil)

// Exporter is a Hubble FlowLogExporter that exports flow logs via gRPC to a remote Timescape server
// supporting the IngesterService.
type Exporter struct {
	log     *slog.Logger
	target  string
	options options

	// This channel is closed when Run returns and is used to signal the Exporter to stop processing
	// events from the Export method.
	stopped chan struct{}

	// tlsConfigBuilder is obtained from resolving options.tlsConfigPromise in Run().
	tlsConfigBuilder certloader.ClientConfigBuilder

	// NOTE: buffer is never closed to avoid possible panic trying to write to a closed channel
	// from the Export method, which is part of our API and can be called concurrently with Run.
	buffer         chan *flowpb.Flow
	connectRetries int

	droppedFlows atomic.Uint64
}

// NewExporter creates a new Exporter with the provided options. You must call Run to start the
// exporter, which will establish a connection to the remote server and begin exporting flow logs.
// The exporter will retry on connection failures using the configured backoff strategy.
func NewExporter(log *slog.Logger, target string, opts ...Option) (*Exporter, error) {
	if target == "" {
		return nil, errors.New("target is empty")
	}

	options := options{
		backoff:                    exponentialBackoff(),
		maxBufferSize:              4096, // Use a similar value as the observer ring buffer size
		reportDroppedFlowsInterval: 1 * time.Minute,
	}
	for _, opt := range opts {
		if err := opt(&options); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}
	scopedLog := log.With(
		logfields.LogSubsys, "hubble-timescape-exporter",
		logfields.Target, target,
	)
	return &Exporter{
		log:     scopedLog,
		target:  target,
		options: options,
		stopped: make(chan struct{}),
		buffer:  make(chan *flowpb.Flow, options.maxBufferSize),
	}, nil
}

// Export implements exporter.FlowLogExporter.
func (s *Exporter) Export(ctx context.Context, ev *v1.Event) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.stopped:
		return nil
	default:
	}

	// Filter the event using the configured allow and deny filters.
	if !filters.Apply(s.options.allowFilters, s.options.denyFilters, ev) {
		return nil
	}

	// Process OnExportEvent hooks.
	for _, f := range s.options.onExportEvent {
		stop, err := f.OnExportEvent(ctx, ev)
		if err != nil {
			s.log.Warn("OnExportEvent hook failed", logfields.Error, err)
		}
		if stop {
			return nil
		}
	}

	// Process the event based on its type.
	switch event := ev.Event.(type) {
	case *flowpb.Flow:
		if s.options.fieldMask.Active() {
			s.options.fieldMask.Copy(s.options.fieldMaskFlow.ProtoReflect(), event.ProtoReflect())
			event = s.options.fieldMaskFlow
		}
		if s.options.nodeName != "" {
			event.NodeName = s.options.nodeName
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.stopped:
			return nil
		case s.buffer <- event:
		default:
			// buffer is full, drop the flow.
			s.droppedFlows.Add(1)
		}
	}

	return nil
}

// Stop implements exporter.FlowLogExporter.
//
// This is a no-op, as the Run method is responsible for handling stopping the exporter when its
// context is canceled.
func (s *Exporter) Stop() error {
	return nil
}

// Run establishes a connection to the remote server and starts exporting flow logs. On failure to
// connect, it retries using the configured backoff strategy. The method blocks until the context is
// canceled.
//
// When the context is canceled, the exporter will stop processing events from the Export method and
// will close any open connections.
func (s *Exporter) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)

	var wg sync.WaitGroup
	wg.Go(func() {
		<-ctx.Done()
		s.log.Debug("context canceled, stopping timescape exporter")
		close(s.stopped)
	})

	if s.options.reportDroppedFlowsInterval > 0 {
		wg.Go(func() {
			log := s.log.With(logfields.Duration, s.options.reportDroppedFlowsInterval)
			log.Debug("starting dropped flows reporting")
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(s.options.reportDroppedFlowsInterval):
					if count := s.droppedFlows.Swap(0); count > 0 {
						log.Warn("dropped flows in the last period",
							logfields.Count, count,
							logfields.Reason, "buffer full",
						)
					}
				}
			}
		})
	}

	err := s.run(ctx)
	cancel()
	wg.Wait()
	for range s.buffer {
		// Drain the buffer.
	}
	return err
}

func (s *Exporter) run(ctx context.Context) error {
	if s.options.tlsConfigPromise != nil {
		tlsConfigBuilder, err := s.options.tlsConfigPromise.Await(ctx)
		if err != nil {
			return fmt.Errorf("failed to get TLS config: %w", err)
		}
		s.tlsConfigBuilder = tlsConfigBuilder
	}

	for {
		s.log.Info("start streaming flow logs")
		err := s.connectAndStream(ctx)
		if err == nil {
			continue
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}

		s.log.Error("failed to stream flow logs", logfields.Error, err)
		s.connectRetries++
		backoffDuration := s.options.backoff.Duration(s.connectRetries)
		s.log.Info("retrying export after backoff",
			logfields.Duration, backoffDuration,
			logfields.Retries, s.connectRetries,
		)
		select {
		case <-time.After(backoffDuration):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// connectAndStream establishes a gRPC stream to the remote server and sends flow logs from the
// buffer.
func (s *Exporter) connectAndStream(ctx context.Context) error {
	s.log.Debug("creating grpc client")
	client, err := s.buildClient()
	if err != nil {
		return fmt.Errorf("failed to build client: %w", err)
	}
	defer func() {
		s.log.Debug("closing grpc client")
		if err := client.Close(); err != nil {
			s.log.Error("failed to close connection", logfields.Error, err)
		}
	}()

	s.log.Debug("opening stream", logfields.Service, tsv1alphapb.IngesterService_Ingest_FullMethodName)
	stream, err := tsv1alphapb.NewIngesterServiceClient(client).Ingest(ctx)
	if err != nil {
		return fmt.Errorf("failed to create stream: %w", err)
	}

	s.log.Debug("stream opened, writing flows from buffer to stream")
	if err := s.streamFlows(stream); err != nil {
		return fmt.Errorf("failed to stream flows: %w", err)
	}
	s.log.Debug("stream ended, close the request stream and wait for the server response")
	if _, err := stream.CloseAndRecv(); err != nil {
		return fmt.Errorf("failed to close stream: %w", err)
	}
	return nil
}

// streamFlows reads flow logs from the buffer and sends them to the gRPC stream.
//
// Note that if this method returns nil, the caller is responsible for closing the stream by calling
// CloseAndRecv() on it.
func (s *Exporter) streamFlows(stream grpc.ClientStreamingClient[tsv1alphapb.IngestRequest, tsv1alphapb.IngestResponse]) error {
	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case flow := <-s.buffer:
			err := stream.Send(&tsv1alphapb.IngestRequest{Data: &tsv1alphapb.IngestRequest_Flow{Flow: flow}})
			if err != nil {
				if errors.Is(err, io.EOF) {
					s.log.Debug("stream has ended, stop writing to stream")
					return nil
				}
				return fmt.Errorf("failed to send flow to stream: %w", err)
			}
			// Reset the connect retries counter now that we know the stream is open and working.
			s.connectRetries = 0
		}
	}
}

// buildClient creates a gRPC client connection to the target server using the configured options.
func (s *Exporter) buildClient() (*grpc.ClientConn, error) {
	var opts []grpc.DialOption
	opts = append(opts, s.options.dialOptions...)
	opts = append(opts, grpc.WithContextDialer(dial.NewContextDialer(s.log, s.options.resolvers...)))
	if s.tlsConfigBuilder == nil {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		// NOTE: gosec is unable to resolve the constant and warns about "TLS
		// MinVersion too low".
		baseConf := &tls.Config{ //nolint:gosec
			MinVersion: minTLSVersion,
		}
		opts = append(opts, grpc.WithTransportCredentials(
			&grpcTLSCredentialsWrapper{
				TransportCredentials: credentials.NewTLS(s.tlsConfigBuilder.ClientConfig(baseConf)),
				baseConf:             baseConf,
				TLSConfig:            s.tlsConfigBuilder,
			},
		))
	}
	// We don't want the grpc client to perform DNS resolution when we use
	// resolvers. As per documentation on `grpc.WithContextDialer`:
	//  Note that gRPC by default performs name resolution on the target passed to
	//  NewClient. To bypass name resolution and cause the target string to be
	//  passed directly to the dialer here instead, use the "passthrough" resolver
	//  by specifying it in the target string, e.g. "passthrough:target".
	target := s.target
	if len(s.options.resolvers) > 0 {
		target = "passthrough:" + strings.TrimPrefix(target, "passthrough:")
	}
	return grpc.NewClient(target, opts...)
}
