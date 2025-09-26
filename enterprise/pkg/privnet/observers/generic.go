//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package observers

import (
	"context"
	"sync/atomic"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

// Event represents a generic event to be observed.
type Event[T, K any] struct {
	Object    T
	EventKind K
}

// Events is a sequence of generic events to be observed.
type Events[T, K any] []Event[T, K]

// Generic implements the common logic for a generic observer, which allows
// batching a set of consecutive events and emitting them together. It mimics
// the behavior of (a stripped down version of) [stream.Buffer], but ensures
// that the queue operation never blocks after that the observer context has
// been cancelled. At that point, any new event attempted to be queued is
// simply discarded.
type Generic[T, K any] struct {
	buf     Events[T, K]
	mu      lock.Mutex
	started atomic.Bool
	stopped atomic.Bool
	wake    chan struct{}
}

func NewGeneric[T, K any]() *Generic[T, K] {
	return &Generic[T, K]{
		wake: make(chan struct{}, 1),
	}
}

// Observe observes a stream of batched events.
func (o *Generic[T, K]) Observe(ctx context.Context, next func(Events[T, K]), complete func(error)) {
	const interval = 50 * time.Millisecond
	var tick <-chan time.Time

	if o.started.Swap(true) {
		panic("Calling [observer.Observe] multiple times is not supported")
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				o.stopped.Store(true)
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

func (o *Generic[T, K]) Queue(ek K, obj T) {
	// The observer stopped, so no need to queue the events.
	if o.stopped.Load() {
		return
	}

	o.mu.Lock()

	// First element in the buffer, wake up the observer to start the flushing timer.
	if len(o.buf) == 0 {
		select {
		case o.wake <- struct{}{}:
		default:
		}
	}

	o.buf = append(o.buf, Event[T, K]{Object: obj, EventKind: ek})
	o.mu.Unlock()
}
