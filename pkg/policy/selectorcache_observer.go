// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package policy

import (
	"slices"
	"sync"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/types"
)

// SelectorCacheObserver receives selector-cache updates for all selectors.
// Callbacks run from a dedicated goroutine that does not hold selector-cache
// locks, but they must push their side effects synchronously before returning.
type SelectorCacheObserver interface {
	SelectorCacheUpdated(types.SelectorUpdates)
}

// observerNotification stores the information needed to notify
// selector cache observers of a committed update. Notifications are queued so
// observers run in FIFO order without holding selector cache lock.
type observerNotification struct {
	update types.SelectorUpdates
	wg     *sync.WaitGroup
}

func (sc *SelectorCache) setObserver(obs SelectorCacheObserver) {
	if sc.observer != nil {
		panic("Selector cache observer already set")
	}
	sc.observer = obs
	sc.observerHandlerDone = nil
}

func (sc *SelectorCache) resetObserver(obs SelectorCacheObserver) chan struct{} {
	if sc.observer != obs {
		panic("Selector cache observer not set")
	}
	sc.observer = nil
	// stop the handler, if any
	sc.observerCond.Signal()

	// let the caller wait for the channel close after unlocking
	return sc.observerHandlerDone
}

func (sc *SelectorCache) selectorUpdated(sel *identitySelector, ids identity.NumericIdentitySlice) {
	if sc.observer != nil {
		sc.pendingSelectorChanges[sel.id] = types.SelectorChange{
			ID:         sel.id,
			Selections: ids,
		}
	}
}

func (sc *SelectorCache) selectorRemoved(sel *identitySelector) {
	if sc.observer != nil {
		sc.pendingSelectorChanges[sel.id] = types.SelectorChange{
			ID:      sel.id,
			Removed: true,
		}
	}
}

func (sc *SelectorCache) queueObserverUpdate(revision types.SelectorRevision, wg *sync.WaitGroup) {
	if sc.observer != nil {
		var changes []types.SelectorChange

		if len(sc.pendingSelectorChanges) > 0 {
			changes = make([]types.SelectorChange, 0, len(sc.pendingSelectorChanges))
			for _, change := range sc.pendingSelectorChanges {
				changes = append(changes, change)
			}
			slices.SortFunc(changes, types.SelectorChangeCompare)
		}

		// Empty updates still advance the selector revision barrier used by xDS
		// policy publication, even when no selector resources changed in the commit,
		// but there is no need to wait it.
		if len(changes) == 0 {
			wg = nil
		}

		update := SelectorUpdates{
			Revision: revision,
			Changes:  changes,
		}

		if wg != nil {
			wg.Add(1)
		}

		sc.observerNotifications = append(sc.observerNotifications, observerNotification{
			update: update,
			wg:     wg,
		})
		if sc.observerHandlerDone == nil {
			sc.observerHandlerDone = make(chan struct{})
			go sc.handleSelectorObserverNotifications()
		}
		sc.observerCond.Signal()
	}
	clear(sc.pendingSelectorChanges)
}

func (sc *SelectorCache) handleSelectorObserverNotifications() {
	for {
		sc.mutex.Lock()
		for sc.observer != nil && len(sc.observerNotifications) == 0 {
			sc.observerCond.Wait()
		}

		// Drain the queued batch under sc.mutex, then release it before invoking
		// callbacks so slow observers do not block later selector-cache commits
		// from enqueueing behind them in FIFO order.
		notifications := sc.observerNotifications
		sc.observerNotifications = nil
		observer := sc.observer
		sc.mutex.Unlock()

		if observer == nil {
			close(sc.observerHandlerDone)
			return
		}

		for _, n := range notifications {
			observer.SelectorCacheUpdated(n.update)

			// Done() is called only after the callback returns, so waiting on the
			// UpdateIdentities waitgroup means the observer has synchronously pushed
			// any selector changes to its sink before later proxy work begins.
			if n.wg != nil {
				n.wg.Done()
			}
		}
	}
}
