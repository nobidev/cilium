//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package kvstore

import (
	"context"
	"sync/atomic"

	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

// EndpointEvent represents an endpoint event received via clustermesh.
type EndpointEvent struct {
	*Endpoint
	resource.EventKind
}

// EndpointEvents is a sequence of endpoint events received via clustermesh.
type EndpointEvents []EndpointEvent

// EndpointsObserver implements [store.Observer] for private network endpoints.
type EndpointsObserver struct {
	buf     EndpointEvents
	mu      lock.Mutex
	started atomic.Bool
	wake    chan struct{}
}

var (
	_ store.Observer                    = (*EndpointsObserver)(nil)
	_ stream.Observable[EndpointEvents] = (*EndpointsObserver)(nil)
)

func NewEndpointObserver() *EndpointsObserver {
	return &EndpointsObserver{
		wake: make(chan struct{}, 1),
	}
}

// Observe observes the stream of endpoint events received via clustermesh.
func (o *EndpointsObserver) Observe(ctx context.Context, next func(EndpointEvents), complete func(error)) {
	const interval = 50 * time.Millisecond
	var tick <-chan time.Time

	if o.started.Swap(true) {
		panic("Calling [EndpointsObserver.Observe] multiple times is not supported")
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				complete(ctx.Err())
				return
			case <-o.wake:
				tick = time.After(interval)
			case <-tick:
				o.mu.Lock()
				buf := o.buf
				o.buf = nil
				o.mu.Unlock()
				next(buf)
			}
		}
	}()
}

func (o *EndpointsObserver) OnUpdate(k store.Key) {
	if ep, ok := k.(*ValidatingEndpoint); ok {
		o.queue(resource.Upsert, &ep.Endpoint)
	}
}

func (o *EndpointsObserver) OnDelete(k store.NamedKey) {
	if ep, ok := k.(*ValidatingEndpoint); ok {
		o.queue(resource.Delete, &ep.Endpoint)
	}
}

func (o *EndpointsObserver) OnSync() {
	o.queue(resource.Sync, nil)
}

func (o *EndpointsObserver) queue(ek resource.EventKind, ep *Endpoint) {
	o.mu.Lock()

	// First element in the buffer, wake up the observe to start the flushing timer.
	if len(o.buf) == 0 {
		select {
		case o.wake <- struct{}{}:
		default:
		}
	}

	o.buf = append(o.buf, EndpointEvent{Endpoint: ep, EventKind: ek})
	o.mu.Unlock()
}
