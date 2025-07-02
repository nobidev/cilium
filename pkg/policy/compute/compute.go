// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package compute

import (
	"context"
	"fmt"
	"sync"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
)

type PolicyRecomputer interface {
	RecomputeIdentityPolicy(identity *identity.Identity, toRev uint64) (<-chan struct{}, error)
	RecomputeIdentityPolicyForAllIdentities(toRev uint64) (*statedb.WatchSet, error)
	UpdatePolicy(idsToRegen set.Set[identity.NumericIdentity], fromRev, toRev uint64)
	GetIdentityPolicyByNumericIdentity(identity identity.NumericIdentity) (Result, statedb.Revision, <-chan struct{}, bool)
	GetIdentityPolicyByIdentity(identity *identity.Identity) (Result, statedb.Revision, <-chan struct{}, bool)
}

type Result struct {
	Identity             identity.NumericIdentity
	NewPolicy, OldPolicy policy.SelectorPolicy
	Revision             uint64
	NeedsRelease         bool
	Err                  error
}

type computeRequest struct {
	identity *identity.Identity
	toRev    uint64
	done     chan struct{}
}

func (r *IdentityPolicyComputer) UpdatePolicy(idsToRegen set.Set[identity.NumericIdentity], _, toRev uint64) {
	for id := range idsToRegen.Members() {
		if idd := r.idmanager.Get(&id); idd != nil {
			_, _ = r.RecomputeIdentityPolicy(idd, toRev)
		} else {
			r.logger.Debug("Policy recomputation skipped due to non-local identity", logfields.Identity, id)
		}
	}
}

// RecomputeIdentityPolicy recomputes the policy for a specific identity.
func (r *IdentityPolicyComputer) RecomputeIdentityPolicy(identity *identity.Identity, toRev uint64) (<-chan struct{}, error) {
	req := computeRequest{
		identity: identity,
		toRev:    toRev,
		done:     make(chan struct{}),
	}
	r.reqsMu.Lock()
	r.reqs = append(r.reqs, req)
	r.reqsMu.Unlock()
	select {
	case r.trigger <- struct{}{}:
	default:
	}
	return req.done, nil
}

// RecomputeIdentityPolicyForAllIdentities recomputes policy for all local identities.
func (r *IdentityPolicyComputer) RecomputeIdentityPolicyForAllIdentities(toRev uint64) (*statedb.WatchSet, error) {
	ws := statedb.NewWatchSet()

	r.logger.Info("Recomputing policy for all identities")
	for _, id := range r.idmanager.GetAll() {
		if ch, err := r.RecomputeIdentityPolicy(id, toRev); err != nil {
			return nil, err
		} else {
			ws.Add(ch)
		}
	}
	return ws, nil
}

func (r *IdentityPolicyComputer) GetIdentityPolicyByNumericIdentity(identity identity.NumericIdentity) (Result, statedb.Revision, <-chan struct{}, bool) {
	return r.tbl.GetWatch(r.db.ReadTxn(), PolicyComputationByIdentity(identity))
}

func (r *IdentityPolicyComputer) GetIdentityPolicyByIdentity(identity *identity.Identity) (Result, statedb.Revision, <-chan struct{}, bool) {
	if identity == nil {
		return Result{}, 0, nil, false
	}
	return r.GetIdentityPolicyByNumericIdentity(identity.ID)
}

// processRequests drains computation requests and processes them in batches.
// Single requests are processed immediately; bursts are naturally batched.
func (r *IdentityPolicyComputer) processRequests(ctx context.Context) error {
	type pending struct {
		computeRequest
		rev statedb.Revision // statedb revision for CompareAndSwap
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-r.trigger:
		}

		r.reqsMu.Lock()
		batch := r.reqs
		r.reqs = nil
		r.reqsMu.Unlock()
		if len(batch) == 0 {
			continue
		}

		r.logger.Debug("Processing policy computation batch", logfields.Count, len(batch))

		// Check which requests actually need computation.
		rtxn := r.db.ReadTxn()
		var work []pending
		for _, req := range batch {
			obj, rev, found := r.tbl.Get(rtxn, PolicyComputationByIdentity(req.identity.ID))
			if found && obj.Revision >= req.toRev {
				close(req.done)
				continue
			}
			work = append(work, pending{req, rev})
		}
		if len(work) == 0 {
			continue
		}

		type result struct {
			pending
			res Result
		}
		results := make([]result, len(work))
		var wg sync.WaitGroup
		for i, w := range work {
			wg.Add(1)
			go func(i int, w pending) {
				defer wg.Done()
				results[i].pending = w
				results[i].res.Identity = w.identity.ID
				results[i].res.NewPolicy, results[i].res.Revision, results[i].res.OldPolicy, results[i].res.NeedsRelease, results[i].res.Err = r.repo.ComputeSelectorPolicy(w.identity, w.toRev)
			}(i, w)
		}
		wg.Wait()

		// Commit in a single WriteTxn.
		wtxn := r.db.WriteTxn(r.tbl)
		for i := range results {
			if results[i].res.Err != nil {
				// This error will result in the relevant endpoints failing
				// to regenerate, which will increment
				// cilium_endpoint_regenerations_total{error=PolicyRegenerationError}.
				r.logger.Error("Policy computation failed for identity",
					logfields.Identity, results[i].res.Identity,
					logfields.Error, results[i].res.Err,
				)
				results[i].res = Result{}
				continue
			}
			// CAS failure only happens if a delete event for the same
			// identity lands between our read and the write, and we're
			// dropping the result anyway in that case.
			if _, _, err := r.tbl.CompareAndSwap(wtxn, results[i].rev, results[i].res); err != nil {
				results[i].res = Result{}
			}
		}
		wtxn.Commit()

		for _, cr := range results {
			close(cr.done)
			if cr.res.Identity == 0 {
				continue // CAS failed
			}
			r.logger.Debug("Policy recomputation completed",
				logfields.Identity, cr.res.Identity,
				logfields.PolicyRevision, cr.toRev,
			)
			if cr.res.OldPolicy != nil && cr.res.NeedsRelease {
				cr.res.OldPolicy.MaybeDetach()
			}
		}
	}
}

func (r *IdentityPolicyComputer) handlePolicyCacheEvent(ctx context.Context, event policy.PolicyCacheChange) error {
	r.logger.Debug("Handle policy cache event", logfields.Identity, event.ID)

	// Handle DELETE first — the identity may already be removed from the manager
	// by the time we process this event, but we still need to clean up statedb.
	if event.Kind == policy.PolicyChangeDelete {
		wtxn := r.db.WriteTxn(r.tbl)
		obj, _, found := r.tbl.Get(wtxn, PolicyComputationByIdentity(event.ID))
		if !found {
			wtxn.Abort()
			return nil
		}
		_, _, err := r.tbl.Delete(wtxn, obj)
		if err != nil {
			wtxn.Abort()
			return fmt.Errorf("failed to delete from statedb policy computation table: %w", err)
		}
		wtxn.Commit()
		return nil
	}

	if event.Identity == nil {
		return nil
	}

	if event.Kind == policy.PolicyChangeInsert {
		_, err := r.RecomputeIdentityPolicy(event.Identity, 0)
		if err != nil {
			return err
		}
	}
	return nil
}
