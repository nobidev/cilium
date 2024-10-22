//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package policy

import (
	"context"
	"sync"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
)

// IdentityChangeBatch contains a set of added and deleted identities
type IdentityChangeBatch struct {
	Added   identity.IdentityMap
	Deleted identity.IdentityMap
}

// identityObserver translates callbacks from the policy trifecta (received via UpdateIdentities) into an
// stream.Observable[IdentityChangeBatch]. In particular, it buffers and replays any changes that happened
// before Observe was called
type identityObserver struct {
	mu   *lock.Mutex
	cond *sync.Cond

	buf []IdentityChangeBatch
}

func newIdentityObserver() *identityObserver {
	mu := new(lock.Mutex)
	cond := sync.NewCond(mu)

	return &identityObserver{
		mu:   mu,
		cond: cond,
		buf:  []IdentityChangeBatch{},
	}
}

// Observe implements an unicast stream.Observable[IdentityChangeBatch]. Similar to stream.FromChannel, only one
// consumer should consume this observable if all values need to be observed, since it is not multicast capable.
func (i *identityObserver) Observe(ctx context.Context, next func(IdentityChangeBatch), complete func(error)) {
	go func() {
		// Wake up the for-loop below if the context is cancelled.
		// See https://pkg.go.dev/context#AfterFunc for a more detailed
		// explanation of this pattern
		cleanupCancellation := context.AfterFunc(ctx, func() {
			i.mu.Lock()
			defer i.mu.Unlock()
			i.cond.Broadcast()
		})
		defer cleanupCancellation()
		defer complete(ctx.Err())

		for {
			// Start of critical section
			i.mu.Lock()

			// Wait for buf to fill up or context cancellation (whichever happens first)
			for len(i.buf) == 0 && ctx.Err() == nil {
				i.cond.Wait()
			}

			// Context was cancelled while waiting, exit
			if ctx.Err() != nil {
				return
			}

			// Dequeue pending items and clear buffer
			pending := i.buf
			i.buf = []IdentityChangeBatch{}

			// End of critical section
			i.mu.Unlock()

			// Send pending items downstream. This is done without the mutex held, since the call to
			// next() is potentially blocking if the consumer is slow
			for _, batch := range pending {
				next(batch)

				// Bail out early if context was cancelled while next() was called
				if ctx.Err() != nil {
					return
				}
			}
		}
	}()

}

// UpdateIdentities implements the identity.UpdateIdentities interface
func (i *identityObserver) UpdateIdentities(added, deleted identity.IdentityMap, wg *sync.WaitGroup) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.buf = append(i.buf, IdentityChangeBatch{added, deleted})
	i.cond.Broadcast()
}
