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
	"iter"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/enterprise/pkg/encryption/policy/types"
	"github.com/cilium/cilium/enterprise/pkg/maps/encryptionpolicymap"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"
)

// newNodeConfig returns the necessary node_config.h definitions to enable the
// encryption policy datapath
func newNodeConfig(cfg types.Config) defines.NodeOut {
	if !cfg.EnableEncryptionPolicy {
		return defines.NodeOut{}
	}

	return defines.NodeOut{
		NodeDefines: map[string]string{
			"ENABLE_ENCRYPTION_POLICY": "1",
		},
	}
}

type reconcilerParams struct {
	cell.In

	JobGroup job.Group
	DB       *statedb.DB

	Config     types.Config
	PolicyMap  *encryptionpolicymap.PolicyMap
	Table      statedb.RWTable[*EncryptionPolicyEntry]
	OpsTracker *reconcilerMetrics
	Metrics    *encryptionPolicyMetrics

	Params reconciler.Params
}

// startEncryptionPolicyReconciler starts a BPF map reconciler that reconciles the contents of the
// encryption-policy StateDB table with the encryption-policy BPF map
func startEncryptionPolicyReconciler(params reconcilerParams, registry *metrics.Registry) (reconciler.Reconciler[*EncryptionPolicyEntry], error) {
	if !params.Config.EnableEncryptionPolicy {
		return nil, nil
	}

	bpf.TablePressureMetrics(
		params.JobGroup,
		registry,
		params.DB,
		params.Table.ToTable(),
		params.PolicyMap,
	)

	return reconciler.Register[*EncryptionPolicyEntry](
		// params
		params.Params,
		// table
		params.Table,
		// clone
		func(e *EncryptionPolicyEntry) *EncryptionPolicyEntry {
			// We can do a shallow copy here and share the Owners slice,
			// since the reconciler only writes to the status field
			cpy := *e
			return &cpy
		},
		// setStatus
		func(e *EncryptionPolicyEntry, s reconciler.Status) *EncryptionPolicyEntry {
			e.Status = s
			return e
		},
		// getStatus
		func(e *EncryptionPolicyEntry) reconciler.Status {
			return e.Status
		},
		// ops
		params.OpsTracker,
		// batchOps
		params.OpsTracker,
	)
}

// reconcilerMetrics wraps the BPF map operations invoked by the reconciler and
// tracks the StateDB revision of issued updates. This is used to measure the
// time it takes for the reconciler to process the items up to a certain revision.
// This measured duration is not correct if there are retries. This tracker
// currently ignores retries, since the revision of retries is not available
// in the current reconciler API. This means that we might consider a batch
// of updates done even if some updates still have pending retries.
// Implementing correct tracking of retries with the current API we would
// require a much more expensive per-item tracking, which would impose
// additional overhead. Thus we opt for a simpler solution that is optimized
// for the happy path.
// The measured durations are always correct if there are no reconciler errors,
// which can be checked via the bpf_reconciliation_errors_total metric.
type reconcilerMetrics struct {
	ops     reconciler.Operations[*EncryptionPolicyEntry]
	metrics *encryptionPolicyMetrics

	mu *lock.Mutex

	lastRevision statedb.Revision
	measurements []reconcilerMeasurement
}

type reconcilerMeasurement struct {
	start    time.Time
	reason   string
	revision statedb.Revision
}

type reconcilerMetricsTracker interface {
	measureReconciliationTime(reason string, revision statedb.Revision)
}

func newReconcilerMetricsTracker(cfg types.Config, policyMap *encryptionpolicymap.PolicyMap, metrics *encryptionPolicyMetrics) *reconcilerMetrics {
	if !cfg.EnableEncryptionPolicy {
		return nil
	}

	ops := bpf.NewMapOps[*EncryptionPolicyEntry](policyMap.Map)
	return &reconcilerMetrics{
		ops:          ops,
		metrics:      metrics,
		mu:           &lock.Mutex{},
		lastRevision: 0,
		measurements: []reconcilerMeasurement{},
	}
}

// finishMeasurementForRevision must be called whenever an object with revision rev
// has been successfully processed.
func (r *reconcilerMetrics) finishMeasurementForRevision(rev statedb.Revision) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.lastRevision = rev

	// iterate pending measurements in revision order (i.e. oldest to newest)
	for len(r.measurements) > 0 {
		// m is the measurement with the lowest revision in queue
		m := r.measurements[0]
		if m.revision > rev {
			break // oldest measurement is waiting for a higher revision
		}

		// only finish measurements if we have observed an exactly matching revision
		if m.revision == rev {
			r.metrics.BPFReconciliationDuration.WithLabelValues(m.reason).Observe(time.Since(m.start).Seconds())
		}

		// remove measurement m from queue
		r.measurements = r.measurements[1:]
		if len(r.measurements) == 0 {
			r.measurements = nil // release slice memory
		}
	}
}

// measureReconciliationTime measures the time it takes to process the item at revision rev.
// This function must be called with monotonically increasing revisions, otherwise no
// measurement will be performed.
func (r *reconcilerMetrics) measureReconciliationTime(reason string, rev statedb.Revision) {
	if !r.metrics.BPFReconciliationDuration.IsEnabled() {
		return // no need to measure if metric is disabled
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.lastRevision >= rev {
		return // revision has already been observed, nothing to measure
	}

	n := len(r.measurements)
	if n > 0 && r.measurements[n-1].revision > rev {
		return // this function must be called with monotonically increasing revisions
	}

	r.measurements = append(r.measurements, reconcilerMeasurement{
		start:    time.Now(),
		reason:   reason,
		revision: rev,
	})
}

// UpdateBatch implements reconciler.BatchOperations[*EncryptionPolicyEntry]
func (r *reconcilerMetrics) UpdateBatch(ctx context.Context, txn statedb.ReadTxn, batch []reconciler.BatchEntry[*EncryptionPolicyEntry]) {
	for _, entry := range batch {
		err := r.ops.Update(ctx, txn, entry.Revision, entry.Object)
		if err != nil {
			r.metrics.BPFReconciliationErrors.WithLabelValues(operationUpdate).Inc()
			entry.Result = err
		} else {
			r.finishMeasurementForRevision(entry.Revision)
		}
	}
}

// DeleteBatch implements reconciler.BatchOperations[*EncryptionPolicyEntry]
func (r *reconcilerMetrics) DeleteBatch(ctx context.Context, txn statedb.ReadTxn, batch []reconciler.BatchEntry[*EncryptionPolicyEntry]) {
	for _, entry := range batch {
		err := r.ops.Delete(ctx, txn, entry.Revision, entry.Object)
		if err != nil {
			r.metrics.BPFReconciliationErrors.WithLabelValues(operationDelete).Inc()
			entry.Result = err
		} else {
			r.finishMeasurementForRevision(entry.Revision)
		}
	}
}

// Update implements reconciler.Operations[*EncryptionPolicyEntry]
func (r *reconcilerMetrics) Update(ctx context.Context, txn statedb.ReadTxn, revision statedb.Revision, obj *EncryptionPolicyEntry) error {
	// only used for retries, just pass through
	return r.ops.Update(ctx, txn, revision, obj)
}

// Delete implements reconciler.Operations[*EncryptionPolicyEntry]
func (r *reconcilerMetrics) Delete(ctx context.Context, txn statedb.ReadTxn, revision statedb.Revision, obj *EncryptionPolicyEntry) error {
	// only used for retries, just pass through
	return r.ops.Delete(ctx, txn, revision, obj)
}

// Prune implements reconciler.Operations[*EncryptionPolicyEntry]
func (r *reconcilerMetrics) Prune(ctx context.Context, txn statedb.ReadTxn, s iter.Seq2[*EncryptionPolicyEntry, uint64]) error {
	err := r.ops.Prune(ctx, txn, s)
	if err != nil {
		r.metrics.BPFReconciliationErrors.WithLabelValues(operationPrune).Inc()
		return err
	}
	return nil
}
