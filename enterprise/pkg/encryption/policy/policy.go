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
	"fmt"
	"log/slog"
	"slices"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/identity"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	networkPolicy "github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/types"
)

// encryptionRule represent a policy rule. All fields are immutable and must
// not be mutated (except for subjectSelector and peerSelector which are
// protected and updated by SelectorCache)
type encryptionRule struct {
	key RuleKey

	subjectSelector networkPolicy.CachedSelector
	subjectNotifier *identityNotifier

	peerSelector networkPolicy.CachedSelector
	peerNotifier *identityNotifier
	peerPorts    []portProto
}

// subjectIdentities returns the list of numeric identities selected by the
// subject selector of this rule r
func (r *encryptionRule) subjectIdentities() []identity.NumericIdentity {
	if r.subjectSelector.IsWildcard() {
		return []identity.NumericIdentity{0} // ANY
	}

	return r.subjectSelector.GetSelections()
}

// peerIdentities returns the list of numeric identities selected by the
// peer selector of this rule r
func (r *encryptionRule) peerIdentities() []identity.NumericIdentity {
	if r.peerSelector.IsWildcard() {
		return []identity.NumericIdentity{0} // ANY
	}

	return r.peerSelector.GetSelections()
}

// cartesianProduct generates the encryption tuples needed to implement this rule
// and passes them to the yield function.
// It does this by computing the cartesian product of (subjects x peers x ports).
func (r *encryptionRule) cartesianProduct(subjects, peers []identity.NumericIdentity) func(yield func(key RuleKey, tuple EncryptionTuple) bool) {
	return func(yield func(key RuleKey, tuple EncryptionTuple) bool) {
		for _, snid := range subjects {
			for _, pnid := range peers {
				for _, pp := range r.peerPorts {
					tuple := EncryptionTuple{
						Subject: snid,
						Peer:    pnid,
						Port:    pp.port,
						Proto:   pp.proto,
					}
					if !yield(r.key, tuple) {
						return
					}
				}
			}
		}
	}
}

// identityNotifier implements networkPolicy.CachedSelectionUser for a given rule
type identityNotifier struct {
	rule *encryptionRule
	e    *Engine

	isSubject bool

	queuedAdds []identity.NumericIdentity
	queuedDels []identity.NumericIdentity
}

// enqueueIdentityChange works like append, but does not re-allocate the slice
// if the destination is nil
func enqueueIdentityChange(slice, elems []identity.NumericIdentity) []identity.NumericIdentity {
	if slice == nil {
		return elems
	} else {
		return append(slice, elems...)
	}
}

// IdentitySelectionUpdated is invoked if the identities of the rule selector
// have changed. We enqueue such changes, so they can later
// (when IdentitySelectionCommit is called) be used to update affected tuples in StateDB.
func (n *identityNotifier) IdentitySelectionUpdated(_ *slog.Logger, selector types.CachedSelector, added, deleted []identity.NumericIdentity) {
	if selector.IsWildcard() {
		return // skip updates for selection changes to wildcard selector
	}

	n.queuedAdds = enqueueIdentityChange(n.queuedAdds, added)
	n.queuedDels = enqueueIdentityChange(n.queuedDels, deleted)
}

// IdentitySelectionCommit is called all identities of an identity change batch
// have been added to the SelectorCache.
// We want to incrementally update the affected tuples in the policy StateDB table.
func (n *identityNotifier) IdentitySelectionCommit(_ *slog.Logger, tx types.SelectorSnapshot) {
	if len(n.queuedAdds)+len(n.queuedDels) == 0 {
		return // skip update if no-op
	}

	if n.isSubject {
		unchangedPeers := n.rule.peerIdentities()
		n.e.incrementalIdentityChange(n.rule,
			n.queuedDels, unchangedPeers,
			n.queuedAdds, unchangedPeers,
		)
	} else {
		unchangedSubjects := n.rule.subjectIdentities()
		n.e.incrementalIdentityChange(n.rule,
			unchangedSubjects, n.queuedDels,
			unchangedSubjects, n.queuedAdds)
	}

	n.queuedAdds = nil
	n.queuedDels = nil
}

func (n *identityNotifier) IsPeerSelector() bool {
	return true
}

func (e *Engine) newIdentityNotifier(rule *encryptionRule, isSubject bool) *identityNotifier {
	return &identityNotifier{
		rule:      rule,
		e:         e,
		isSubject: isSubject,
	}
}

// newRule returns a encryptionRule that has been added to the SelectorCache
func (e *Engine) newRule(key RuleKey, rule parsedSelectorRule) *encryptionRule {
	r := &encryptionRule{
		key:       key,
		peerPorts: rule.peerPorts,
	}

	r.subjectNotifier = e.newIdentityNotifier(r, true)
	css, _ := e.selectorCache.AddSelectors(r.subjectNotifier, networkPolicy.EmptyStringLabels, rule.subject)
	if css.Len() != 1 {
		panic(fmt.Sprintf("unexpected length of selectors for subjectNotifier 1 != %d", css.Len()))
	}
	r.subjectSelector = css[0]

	r.peerNotifier = e.newIdentityNotifier(r, false)
	css, _ = e.selectorCache.AddSelectors(r.peerNotifier, networkPolicy.EmptyStringLabels, rule.peer)
	if css.Len() != 1 {
		panic(fmt.Sprintf("unexpected length of selectors for peerNotifier 1 != %d", css.Len()))
	}
	r.peerSelector = css[0]

	return r
}

// replaceRules is invoked if the parsed selector rules for a given resource have
// changed. It inserts all parsed selector into to the selector cache and removes
// any old selectors from the selector cache if they have been previously associated
// with this resource.
// It returns a list of the newRules now known to the selector cache,
// and returns a list of oldRuleKeys identifying the rules which have been deleted from
// the selector cache.
func (e *Engine) replaceRules(resourceKey resource.Key, rules []parsedSelectorRule) (newRules []*encryptionRule, oldRuleKeys []RuleKey) {
	e.rulesMutex.Lock()
	defer e.rulesMutex.Unlock()

	// Extract old rules to remove them the selector cache later
	var oldRules []*encryptionRule
	if old, ok := e.rulesByResource[resourceKey]; ok {
		oldRules = old
		delete(e.rulesByResource, resourceKey)
	}

	// Insert new rules into selector cache
	if len(rules) > 0 {
		newRules = make([]*encryptionRule, 0, len(rules))

		// Always bump the revision when replacing rules. This ensures that the old rule
		// and new rule are separate owners of the StateDB entries, which simplifies
		// upserts and deletes of EncryptionTuples
		e.rulesRevision++
		newRevision := e.rulesRevision
		for i, r := range rules {
			newRule := e.newRule(RuleKey{Resource: resourceKey, Index: uint(i), Revision: newRevision}, r)
			newRules = append(newRules, newRule)
		}
		e.rulesByResource[resourceKey] = newRules
	}

	if len(oldRules) > 0 {
		// Remove old rules from selector cache after the new ones have been added. This
		// ensures that the cached selectors are not unnecessarily removed and re-created
		oldRuleKeys = make([]RuleKey, 0, len(oldRules))
		for _, oldRule := range oldRules {
			e.selectorCache.RemoveSelector(oldRule.subjectSelector, oldRule.subjectNotifier)
			e.selectorCache.RemoveSelector(oldRule.peerSelector, oldRule.peerNotifier)
			oldRuleKeys = append(oldRuleKeys, oldRule.key)
		}
	}

	// Update metric if needed
	if e.metrics.EncryptionPolicyRules.IsEnabled() {
		e.metrics.EncryptionPolicyRules.Add(float64(len(newRules) - len(oldRules)))
	}

	return newRules, oldRuleKeys
}

// upsertEncryptionPolicy parses and then processes an encryption policy update or
// insert
func (e *Engine) upsertEncryptionPolicy(resourceKey resource.Key, spec iso_v1alpha1.ClusterwideEncryptionPolicySpec) error {
	policyRules, err := parseEncryptionPolicy(resourceKey, spec)
	if err != nil {
		return err
	}

	newRules, oldRuleKeys := e.replaceRules(resourceKey, policyRules)

	txn := e.db.WriteTxn(e.policyTable)
	defer txn.Commit()

	// We first insert new tuples and then remove old ones. Because oldRuleKeys and newRules
	// have distinct RuleKeys, this ensures that we don't unnecessarily delete and re-create
	// the same tuple
	for _, newRule := range newRules {
		tupleIter := newRule.cartesianProduct(newRule.subjectIdentities(), newRule.peerIdentities())
		for key, tuple := range tupleIter {
			e.insertTuple(txn, key, tuple)
		}
	}

	// Remove all entries only referencing oldRule
	for _, oldRule := range oldRuleKeys {
		e.deleteTuplesForRule(txn, oldRule)
	}

	e.reconcilerTracker.measureReconciliationTime(reasonPolicyUpdate, e.policyTable.Revision(txn))
	return nil
}

// deleteEncryptionPolicy removes all state related to the deleted resource
// from the selector cache and from StateDB
func (e *Engine) deleteEncryptionPolicy(resourceKey resource.Key) error {
	_, oldRuleKeys := e.replaceRules(resourceKey, nil)

	txn := e.db.WriteTxn(e.policyTable)
	defer txn.Commit()
	for _, oldRule := range oldRuleKeys {
		e.deleteTuplesForRule(txn, oldRule)
	}

	e.reconcilerTracker.measureReconciliationTime(reasonPolicyUpdate, e.policyTable.Revision(txn))
	return nil
}

// incrementalIdentityChange is invoked when the identities for the provided
// rule have changed and updates the resulting tuples in the StateDB table.
// This function expects Engine.identityChangeTxn to contain the current write
// transaction.
func (e *Engine) incrementalIdentityChange(rule *encryptionRule, deletedSubjects, deletedPeers, addedSubject, addedPeers []identity.NumericIdentity) {
	txnPtr := e.identityChangeTxn.Load()
	if txnPtr == nil {
		// This should never happen. However, in the unlikely case that it does,
		// we just initiate a short-lived transaction. This may lead to partial
		// updates being observed downstream, but that's still better than
		// skipping the update completely.
		e.log.Error("BUG: Internal error while attempting to obtain identity change write transaction. " +
			"Encryption policy map entries may be temporarily inconsistent " +
			"Please report this bug to Cilium developers.")

		fallbackTxn := e.db.WriteTxn(e.policyTable)
		defer fallbackTxn.Commit()
		txnPtr = &fallbackTxn
	}

	tuplesToAdd := rule.cartesianProduct(addedSubject, addedPeers)
	for key, tuple := range tuplesToAdd {
		e.insertTuple(*txnPtr, key, tuple)
	}

	tuplesToDelete := rule.cartesianProduct(deletedSubjects, deletedPeers)
	for key, tuple := range tuplesToDelete {
		e.deleteTuple(*txnPtr, key, tuple)
	}
}

// insertTuple associates the provided tuple with the owner in StateDB.
// If there is already a EncryptionPolicyEntry for this tuple, then the
// RuleKey owner is added to the list of owners on the existing entry.
// If there is no entry for this tuple, then a new entry
// (with the RuleKey as an owner) is created.
func (e *Engine) insertTuple(txn statedb.WriteTxn, owner RuleKey, tuple EncryptionTuple) {
	entry, _, _ := e.policyTable.Get(txn, EncryptionPolicyTupleIndex.Query(tuple))
	if entry == nil {
		// Create a new entry
		entry = &EncryptionPolicyEntry{
			EncryptionTuple: tuple,
			Owners:          []RuleKey{},
			Status:          reconciler.StatusPending(),
		}
	} else {
		// Copy, since modifying objects directly is not allowed.
		entry = entry.DeepCopy()
	}

	if !slices.Contains(entry.Owners, owner) {
		entry.Owners = append(entry.Owners, owner)
	}

	_, _, err := e.policyTable.Insert(txn, entry)
	if err != nil {
		e.log.Error("BUG: Internal error while attempting to update encryption policy tuple. "+
			"Traffic may be leaked in plaintext. "+
			"Please report this bug to Cilium developers.",
			logfields.Key, owner,
			logfields.Error, err)
	}
}

// deleteTuple dissociates the provided tuple with the owner in StateDB.
// It does this by finding the EncryptionPolicyEntry entry belonging to the
// provided tuple and removing the owner RuleKey from the owners list.
// If the entry is owner-less after this operation, it is removed from the table.
func (e *Engine) deleteTuple(txn statedb.WriteTxn, owner RuleKey, tuple EncryptionTuple) {
	entry, _, _ := e.policyTable.Get(txn, EncryptionPolicyTupleIndex.Query(tuple))
	if entry == nil {
		// nothing to do
		return
	}

	// Copy, since modifying objects directly is not allowed.
	entry = entry.DeepCopy()

	entry.Owners = slices.DeleteFunc(entry.Owners, func(entryKey RuleKey) bool {
		return entryKey == owner
	})

	// Last owner reference removed, remove entry from map
	var err error
	if len(entry.Owners) == 0 {
		_, _, err = e.policyTable.Delete(txn, entry)
	} else {
		_, _, err = e.policyTable.Insert(txn, entry)
	}
	if err != nil {
		e.log.Error("BUG: Internal error while attempting to delete encryption policy tuple. "+
			"Encryption policy map entries will be leaked. "+
			"Please report this bug to Cilium developers.",
			logfields.Key, owner,
			logfields.Error, err)
	}
}

// deleteTuple dissociates the provided owner RuleKey from all tuples in StateDB.
// If an entry is owner-less after this operation, it is removed from the table.
func (e *Engine) deleteTuplesForRule(txn statedb.WriteTxn, owner RuleKey) {
	entriesByRuleKey := e.policyTable.List(txn, EncryptionPolicyRuleKeyIndex.Query(owner))
	for entry := range entriesByRuleKey {
		// Copy, since modifying objects directly is not allowed.
		entry = entry.DeepCopy()

		entry.Owners = slices.DeleteFunc(entry.Owners, func(entryKey RuleKey) bool {
			return entryKey == owner
		})

		// Last owner reference removed, remove entry from map
		var err error
		if len(entry.Owners) == 0 {
			_, _, err = e.policyTable.Delete(txn, entry)
		} else {
			_, _, err = e.policyTable.Insert(txn, entry)
		}
		if err != nil {
			e.log.Error("BUG: Internal error while attempting to delete encryption policy tuple. "+
				"Encryption policy map entries will be leaked. "+
				"Please report this bug to Cilium developers.",
				logfields.Key, owner,
				logfields.Error, err)
		}
	}
}
