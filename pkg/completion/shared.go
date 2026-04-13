// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package completion

import (
	"slices"

	"github.com/cilium/cilium/pkg/lock"
)

// SharedResult fans out one eventual completion result to many waiters.
type SharedResult struct {
	lock lock.Mutex

	id string

	completed bool
	err       error
	waiters   []*Completion
}

func (r *SharedResult) ID() string {
	if r.id == "" {
		return "SharedResult"
	}
	return r.id
}

func (r *SharedResult) CleanupAfterWait(c *Completion) {
	r.removeWaiter(c)
}

// NewSharedResult returns an empty SharedResult.
func NewSharedResult(id string) *SharedResult {
	return &SharedResult{id: id}
}

// SharedResultValue returns an empty SharedResult value with the given
// diagnostic identifier.
func SharedResultValue(id string) SharedResult {
	return SharedResult{id: id}
}

// AddWaiter adds a waiter from the given wait group. If the shared result has
// already completed, the waiter is completed immediately with the stored
// result.
func (r *SharedResult) AddWaiter(wg *WaitGroup, callback func(error)) *Completion {
	if wg == nil {
		return nil
	}

	c := wg.AddCompletionWithCallback(r, callback)

	var err error
	completeImmediately := false

	r.lock.Lock()
	if r.completed {
		err = r.err
		completeImmediately = true
	} else {
		r.waiters = append(r.waiters, c)
	}
	r.lock.Unlock()

	if completeImmediately {
		c.Complete(err)
	}

	return c
}

func (r *SharedResult) removeWaiter(c *Completion) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.waiters = slices.DeleteFunc(r.waiters, func(waiter *Completion) bool {
		return waiter == c
	})
}

// Complete completes all current and future waiters with the given result.
// Idempotent.
func (r *SharedResult) Complete(err error) error {
	r.lock.Lock()
	if r.completed {
		err = r.err
		r.lock.Unlock()
		return err
	}

	r.completed = true
	r.err = err

	waiters := r.waiters
	r.waiters = nil
	r.lock.Unlock()

	for _, waiter := range waiters {
		if waiter != nil {
			waiter.Complete(err)
		}
	}

	return err
}
