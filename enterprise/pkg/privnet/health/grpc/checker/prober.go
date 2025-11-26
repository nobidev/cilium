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
	"io"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/cilium/stream"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	api "github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/api/v1"
	"github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// prober implements the logic probing a given INB for healthiness.
type prober struct {
	log *slog.Logger
	cfg config.Config

	client api.HealthClient
	self   *api.Node

	started atomic.Bool
	state   tables.INBNodeState

	obs      stream.Observable[tables.INBNodeState]
	emit     func(tables.INBNodeState)
	complete func(error)
}

func newProber(log *slog.Logger, cfg config.Config, cl api.HealthClient, self *api.Node) *prober {
	mcast, emit, complete := stream.Multicast[tables.INBNodeState](stream.EmitLatest)

	return &prober{
		log: log,
		cfg: cfg,

		client: cl,
		self:   self,

		obs:      mcast,
		emit:     emit,
		complete: complete,
	}
}

// Observe allows to observe INB health transitions. The latest transition, if
// already occurred, is replayed when subscribing.
func (p *prober) Observe(ctx context.Context, next func(tables.INBNodeState), complete func(error)) {
	p.obs.Observe(ctx, next, complete)
}

// Run starts the health check loop, continuously probing the INB health status
// according to the configuration settings.
func (p *prober) Run(ctx context.Context) {
	var (
		wg sync.WaitGroup

		sender = make(chan func(*api.ProbeRequest) error)
		recv   = make(chan api.ProbeResponse_ServingStatus)

		// Rate limit failure messages, to prevent flooding in case of tight intervals.
		logrl = rate.NewLimiter(rate.Every(1*time.Minute), 1)
	)

	if p.started.Swap(true) {
		logging.Panic(p.log, "Cannot start [prober] twice")
	}

	defer wg.Wait()
	defer close(recv)
	wg.Go(func() { p.loop(sender, recv) })

	p.log.Info("Starting probing health of INB")
	for {
		stream, err := p.client.Probe(ctx)
		if err != nil {
			if logrl.Allow() {
				p.log.Warn("Failed starting probing health of INB. Retrying", logfields.Error, err)
			}
			goto retry
		}

		p.log.Info("Successfully started probing health of INB")
		sender <- stream.Send
		for {
			response, err := stream.Recv()
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				break
			}

			st, ok := status.FromError(err)
			if ok && st.Code() == codes.Unavailable {
				p.log.Info("Health probe stream closed: server is unavailable")
				break
			}

			if err != nil {
				p.log.Warn("Health probe stream aborted", logfields.Error, err)
				break
			}

			recv <- response.GetStatus()
		}

	retry:
		select {
		case <-time.After(p.cfg.Interval):
		case <-ctx.Done():
			p.log.Info("Stopping probing health of INB")
			return
		}
	}
}

// loop implements the loop to send health check probes and handle health transitions
// based on the received responses and possible timeouts.
func (p *prober) loop(sender <-chan func(*api.ProbeRequest) error, recv <-chan api.ProbeResponse_ServingStatus) {
	var (
		send func()

		sendC   <-chan time.Time
		timeout = time.NewTimer(p.cfg.Timeout)

		request = &api.ProbeRequest{
			Self:     p.self,
			Interval: durationpb.New(p.cfg.Interval),
			Timeout:  durationpb.New(p.cfg.Timeout),
		}
	)

	defer p.complete(nil)
	for {
		select {
		// A new stream got established, time to send the first probe.
		case snd := <-sender:
			send = func() {
				err := snd(request)
				if err != nil && !errors.Is(err, io.EOF) {
					p.log.Info("Failed sending health probe", logfields.Error, err)
				}
			}

			send()

		// Time to send a new probe.
		case <-sendC:
			send()

		// We received a new response. Process it and reset the timers.
		case status, ok := <-recv:
			if !ok {
				return
			}

			switch status {
			case api.ProbeResponse_SERVING:
				p.set(tables.INBNodeStateHealthy, "Successful health probe")
			default:
				p.set(tables.INBNodeStateUnhealthy, "Denied by INB")
			}

			sendC = time.After(p.cfg.Interval)
			timeout.Reset(p.cfg.Timeout)

		// We did not receive a response before the timeout.
		case <-timeout.C:
			p.set(tables.INBNodeStateUnhealthy, "Timeout")
		}
	}
}

// set updates the state associated with the given INB.
func (p *prober) set(state tables.INBNodeState, reason string) {
	if p.state == state {
		return
	}

	p.log.Info("INB health transition occurred",
		logfields.Previous, p.state,
		logfields.State, state,
		logfields.Reason, reason,
	)

	p.state = state
	p.emit(state)
}
