//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package doubleproxy

import (
	"context"
	"maps"
	"math"
	"sync"

	"github.com/cilium/cilium/pkg/lock"
)

type AckTracker struct {
	rev  uint64
	cond *sync.Cond
}

func NewAckTracker() *AckTracker {
	return &AckTracker{
		cond: sync.NewCond(&lock.Mutex{}),
	}
}

func (at *AckTracker) Ack(rev uint64) {
	at.cond.L.Lock()
	if rev > at.rev {
		at.rev = rev
	}
	at.cond.Broadcast()
	at.cond.L.Unlock()
}

func (at *AckTracker) done() {
	at.Ack(math.MaxUint64)
}

func (at *AckTracker) WaitFor(ctx context.Context, rev uint64) error {
	// Allow callers to bail out by cancelling the context
	cleanupCancellation := context.AfterFunc(ctx, func() {
		// We need to acquire cond.L here to be sure that the
		// Broadcast won't occur before the call to Wait, which would result
		// in a missed signal.
		at.cond.L.Lock()
		defer at.cond.L.Unlock()
		at.cond.Broadcast()
	})
	defer cleanupCancellation()

	at.cond.L.Lock()
	defer at.cond.L.Unlock()
	for at.rev < rev {
		at.cond.Wait()
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}

type AckTrackers struct {
	l        lock.Mutex
	trackers map[*AckTracker]struct{}
}

func NewAckTrackers() *AckTrackers {
	return &AckTrackers{
		trackers: make(map[*AckTracker]struct{}, 1),
	}
}

func (ats *AckTrackers) Register() *AckTracker {
	at := NewAckTracker()
	ats.l.Lock()
	defer ats.l.Unlock()
	ats.trackers[at] = struct{}{}
	return at
}

func (ats *AckTrackers) Unregister(at *AckTracker) {
	ats.l.Lock()
	defer ats.l.Unlock()
	delete(ats.trackers, at)
	at.done() // wake all waiting on this
}

func (ats *AckTrackers) WaitFor(ctx context.Context, rev uint64) error {
	ats.l.Lock()
	trackers := maps.Clone(ats.trackers)
	ats.l.Unlock()
	for at := range trackers {
		if err := at.WaitFor(ctx, rev); err != nil {
			return err
		}
	}
	return nil
}
