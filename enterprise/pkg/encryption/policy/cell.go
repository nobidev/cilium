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
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/cilium/stream"

	"github.com/cilium/cilium/enterprise/pkg/encryption/policy/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	networkPolicy "github.com/cilium/cilium/pkg/policy"
)

var Cell = cell.Module(
	"encryption-policy",
	"Encryption Policy Control-Plane",

	// Registers command-line flag
	cell.Config(defaultConfig),

	// K8s resource watcher
	cell.ProvidePrivate(isovalentClusterwideEncryptionPolicyResource),

	// Register StateDB table
	cell.Provide(NewEncryptionPolicyTable),
	cell.Invoke(statedb.RegisterTable[*EncryptionPolicyEntry]),

	// Metrics
	metrics.Metric(newEncryptionPolicyMetrics),

	// Provide BPF datapath configuration, BPF map pressure metrics and BPF map reconciler
	cell.Provide(newNodeConfig),
	cell.ProvidePrivate(
		newReconcilerMetricsTracker,
		startEncryptionPolicyReconciler,
	),

	// Start the encryption policy subsystem
	cell.Invoke(newSelectiveEncryptionEngine),
)

const (
	policyInitializerName   = "isovalentclusterwideencryptionpolicy-synced"
	identityInitializerName = "identities-synced"

	policyUpdateObserver   = "encryption-policy-resource-events"
	identityUpdateObserver = "encryption-policy-identity-events"
)

var defaultConfig = types.Config{
	EnableEncryptionPolicy: false,
}

func isovalentClusterwideEncryptionPolicyResource(cfg types.Config, lc cell.Lifecycle, cs client.Clientset) (resource.Resource[*iso_v1alpha1.IsovalentClusterwideEncryptionPolicy], error) {
	if !(cs.IsEnabled() && cfg.EnableEncryptionPolicy) {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*iso_v1alpha1.IsovalentClusterwideEncryptionPolicyList](cs.IsovalentV1alpha1().IsovalentClusterwideEncryptionPolicies()),
	)
	return resource.New[*iso_v1alpha1.IsovalentClusterwideEncryptionPolicy](lc, lw, resource.WithMetric("IsovalentClusterwideEncryptionPolicy")), nil
}

type engineParams struct {
	cell.In

	Log       *slog.Logger
	Lifecycle cell.Lifecycle
	Config    types.Config
	Registry  job.Registry
	Health    cell.Health

	IdentityChanges stream.Observable[cache.IdentityChange]
	DaemonConfig    *option.DaemonConfig
	ICEPResource    resource.Resource[*iso_v1alpha1.IsovalentClusterwideEncryptionPolicy]

	StateDB           *statedb.DB
	PolicyTable       statedb.RWTable[*EncryptionPolicyEntry]
	Reconciler        reconciler.Reconciler[*EncryptionPolicyEntry]
	ReconcilerTracker *reconcilerMetrics

	Metrics *encryptionPolicyMetrics
}

// newSelectiveEncryptionEngine creates a new instance of encryption policy engine
// and starts jobs feeding the engine with policy and identity changes
func newSelectiveEncryptionEngine(params engineParams) *Engine {
	if !params.Config.EnableEncryptionPolicy {
		return nil
	}

	if !params.DaemonConfig.EnableWireguard {
		params.Log.Error("Encryption Policy requires WireGuard to be enabled")
		return nil
	}

	// Initializers prevent the reconciler from pruning old entries from the BPF map
	// until we have had a chance to recompute the new BPF map state after we observed
	// all encryption policies and all indentities both.
	txn := params.StateDB.WriteTxn(params.PolicyTable)
	policyInitializer := params.PolicyTable.RegisterInitializer(txn, policyInitializerName)
	identityInitializer := params.PolicyTable.RegisterInitializer(txn, identityInitializerName)
	txn.Commit()

	engine := &Engine{
		log:           params.Log,
		selectorCache: networkPolicy.NewSelectorCache(identity.ListReservedIdentities()),

		db:                params.StateDB,
		policyTable:       params.PolicyTable,
		reconciler:        params.Reconciler,
		reconcilerTracker: params.ReconcilerTracker,

		policyInitializer:   policyInitializer,
		identityInitializer: identityInitializer,

		metrics: params.Metrics,

		rulesByResource: map[resource.Key][]*encryptionRule{},
	}

	// Batches identity changes
	identityChanges := bufferIdentityUpdates(params.IdentityChanges)

	// Custom job group to obtain runtime metrics
	jobGroup := params.Registry.NewGroup(params.Health,
		job.WithMetrics(params.Metrics),
		job.WithLogger(params.Log),
	)

	engine.log.Info("Starting encryption-policy subsystem")
	jobGroup.Add(job.Observer(identityUpdateObserver, engine.handleIdentityChange, identityChanges))
	jobGroup.Add(job.Observer(policyUpdateObserver, engine.handlePolicyChange, params.ICEPResource))
	params.Lifecycle.Append(jobGroup)

	return engine
}

// Engine implements the computation of BPF map state from policy and identity changes.
//
// It does this by reacting to changes in IsovalentClusterwideEncryptionPolicy
// resources and Cilium security identities.
//
// When this engine observes a new IsovalentClusterwideEncryptionPolicy resource,
// it will validate and parse that resource (see parse.go), and then add each
// subject and peer selector of the policy into a private instance of the
// selector cache. The selector cache then provides us with a list of identities
// selected by each selector, thus allowing us to compute the required BPF map
// tuples which are based on numeric identities.
//
// When the engine observes identity changes, it informs the selector cache about
// that change, which in turn will inform us (via {peer,subjectIdentityNotifier})
// about the affected policy selectors (and the policy rules the affected selectors
// belong to). For every policy rule affected by the identity change, we compute
// the set of tuples to insert or remove from the BPF map.
//
// The engine itself does not write directly to the BPF map. Instead, it stores
// the computed EncryptionTuple in a StateDB table. Every StateDB entry
// corresponds to exactly one entry in the BPF map. In the StateDB table,
// we keep track of all currently live tuples, as well as the owning policy
// rule(s) that generated the tuple.
//
// The actual BPF map itself is updated by a BPF map reconciler that subscribes
// to updates to EncryptionPolicyEntry and reconciles the StateDB state with the
// BPF map accordingly.
type Engine struct {
	log           *slog.Logger
	selectorCache *networkPolicy.SelectorCache

	db                *statedb.DB
	policyTable       statedb.RWTable[*EncryptionPolicyEntry]
	identityChangeTxn atomic.Pointer[statedb.WriteTxn]

	reconciler        reconciler.Reconciler[*EncryptionPolicyEntry]
	reconcilerTracker reconcilerMetricsTracker

	policyInitializer   func(txn statedb.WriteTxn)
	identityInitializer func(txn statedb.WriteTxn)

	metrics *encryptionPolicyMetrics

	// rulesMutex protects access to rulesRevision and rulesByResource, but not
	// to the stored encryptionRule themselves (they are immutable and might
	// be read without the mutex held)
	rulesMutex      lock.Mutex
	rulesRevision   uint64
	rulesByResource map[resource.Key][]*encryptionRule
}

func (e *Engine) finishInitializer(initializer func(txn statedb.WriteTxn)) {
	txn := e.db.WriteTxn(e.policyTable)
	initializer(txn)
	txn.Commit()
}

// handlePolicyChange reacts to changes in IsovalentClusterwideEncryptionPolicy resources (invoked by an observer job)
func (e *Engine) handlePolicyChange(ctx context.Context, event resource.Event[*iso_v1alpha1.IsovalentClusterwideEncryptionPolicy]) error {
	e.log.Debug("Handling policy event", slog.Any("kind", event.Kind), slog.Any("obj", event.Object))
	var err error
	switch event.Kind {
	case resource.Upsert:
		err = e.upsertEncryptionPolicy(event.Key, event.Object.Spec)
	case resource.Delete:
		err = e.deleteEncryptionPolicy(event.Key)
	case resource.Sync:
		e.log.Debug("Encryption policies synced")
		e.finishInitializer(e.policyInitializer)
	}
	if err != nil {
		e.log.Warn("Unable to handle policy event",
			slog.Any("kind", event.Kind), slog.Any("resource", event.Key),
			slog.Any("error", err))
	}
	event.Done(err)
	return nil
}

// handleIdentityChange reacts to changes in Cilium identities (invoked by an observer job)
func (e *Engine) handleIdentityChange(ctx context.Context, events []cache.IdentityChange) error {
	e.log.Debug("Updating selector cache due to identity change(s)", slog.Any("events", events))

	// Start a new transaction here. This is needed because an update to a single
	// identity may lead multiple subject and peer selectors being notified
	// separately. To avoid downstream consumers observing partial updates (e.g.
	// subject identities have been updated, but peer identities are still
	// pending), we create a write transaction here that is then used to process
	// all updates stemming from this particular batch.
	wg := sync.WaitGroup{}
	txn := e.db.WriteTxn(e.policyTable)
	e.identityChangeTxn.Store(&txn)

	// Waiting on the WaitGroup here is fine, as our selector cache users
	// (subjectIdentityNotifier and peerIdentityNotifier) do not perform any
	// blocking operations (only StateDB updates), but we still want to make
	// sure that all updates are processed before we commit the transaction
	// and handle the next batch
	var identitiesSynced bool
	defer func() {
		wg.Wait()
		// Measure time it takes to reconcile
		e.reconcilerTracker.measureReconciliationTime(reasonIdentityUpdate, e.policyTable.Revision(txn))

		// Clear current transaction and commit
		e.identityChangeTxn.Store(nil)
		txn.Commit()
		// Finish initializer after the identity transaction is committed
		// to avoid a deadlock
		if identitiesSynced {
			e.finishInitializer(e.identityInitializer)
		}
	}()

	// Split the identity change batch into two disjunct "added" and "deleted"
	// sets. This is a requirement to call UpdateIdentities.
	added := identity.IdentityMap{}
	deleted := identity.IdentityMap{}
	for _, ev := range events {
		switch ev.Kind {
		case cache.IdentityChangeUpsert:
			// coalesce with potential previous deletion
			add := ev.Labels.LabelArray()
			if prevDel, ok := deleted[ev.ID]; ok && prevDel.Equals(add) {
				delete(deleted, ev.ID)
			} else {
				added[ev.ID] = add
			}
		case cache.IdentityChangeDelete:
			// coalesce with potential previous addition
			del := ev.Labels.LabelArray()
			if prevAdd, ok := added[ev.ID]; ok && prevAdd.Equals(del) {
				delete(added, ev.ID)
			} else {
				deleted[ev.ID] = del
			}
		case cache.IdentityChangeSync:
			e.log.Debug("Identities synced")
			identitiesSynced = true // read in defer statement
		}
	}
	e.selectorCache.UpdateIdentities(added, deleted, &wg)

	return nil
}
