//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package diagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	ipa_sys "github.com/isovalent/ipa/system_status/v1alpha"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/hubble/exporter"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

// The diagnostics controller periodically evaluates all known conditions
// and updates the entries in the conditions table.
type controller struct {
	controllerParams

	startedAt  time.Time
	envBuilder environmentBuilder
}

type controllerParams struct {
	cell.In

	Log             *slog.Logger
	MetricsRegistry *metrics.Registry
	Jobs            job.Group
	Config          Config
	DB              *statedb.DB
	Conditions      statedb.RWTable[ConditionStatus]
	Metrics         diagnosticMetrics
	SystemID        *ipa_sys.SystemID
}

func registerController(p controllerParams) error {
	c := controller{
		controllerParams: p,
		startedAt:        time.Now(),
		envBuilder: environmentBuilder{
			interval: p.Config.DiagnosticsInterval,
			registry: p.MetricsRegistry,
		},
	}
	p.Jobs.Add(job.OneShot(
		"evalLoop",
		c.evalLoop,
		job.WithShutdown(),
	))
	return nil
}

func (c *controller) evalLoop(ctx context.Context, health cell.Health) error {
	var fileEncoder *json.Encoder

	if c.Config.DiagnosticsExportFile != "" {
		fw, err := exporter.FileWriter(exporter.FileWriterConfig{
			Filename: c.Config.DiagnosticsExportFile,
			MaxSize:  10 * 1024 * 1024, // 10MB
		})()
		if err != nil {
			return fmt.Errorf("failed to create a file writer: %w", err)
		}
		defer fw.Close()
		fileEncoder = json.NewEncoder(fw)
	}

	// Evaluate once to gather used constants and then evaluate the configuration.
	{
		env := c.envBuilder.build()
		env.usedConstants = sets.New[string]()
		now := time.Now()
		for cond := range c.Conditions.All(c.DB.ReadTxn()) {
			evalCondition(env.use(&cond, now), cond.Condition)
		}
		if err := c.Config.Validate(env.usedConstants.UnsortedList()); err != nil {
			return fmt.Errorf("invalid configuration: %w", err)
		}
	}

	ticker := time.NewTicker(c.Config.DiagnosticsInterval)
	defer ticker.Stop()

	health.OK(fmt.Sprintf("Evaluating every %s", c.Config.DiagnosticsInterval))

	knownConditions := sets.New[ConditionID]()
	var newConditions []ConditionID

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		env := c.envBuilder.build()
		now := time.Now()

		wtxn := c.DB.WriteTxn(c.Conditions)
		defer wtxn.Abort()

		totalFailures := 0
		// Evaluate the conditions
		for cond := range c.Conditions.All(wtxn) {
			cond.Latest.EvaluatedAt = now
			cond.Latest.Message, cond.Latest.Severity = evalCondition(
				env.use(&cond, now),
				cond.Condition,
			)
			if cond.Latest.Severity != OK {
				cond.LastFailure = cond.Latest
				cond.FailedCount++
				totalFailures++
			}
			cond.TotalCount++

			c.Conditions.Insert(wtxn, cond)

			if !knownConditions.Has(cond.Condition.ID) {
				newConditions = append(newConditions, cond.Condition.ID)
				knownConditions.Insert(cond.Condition.ID)
			}
		}
		rtxn := wtxn.Commit()

		if fileEncoder != nil {
			// Write out the metadata for any new conditions
			if len(newConditions) > 0 {
				// New conditions have been registered since the last evaluation. Write out a metadata
				// update.
				if err := c.writeMetadataUpdate(fileEncoder, rtxn, newConditions); err != nil {
					c.Log.Warn("Failed to write metadata", logfields.Error, err)
				} else {
					newConditions = nil
				}
			}

			// Write out the status update
			if err := c.writeStatusUpdate(fileEncoder, rtxn); err != nil {
				c.Log.Warn("failed to write status update", logfields.Error, err)
			}
		}

		c.Metrics.ControllerDuration.Observe(float64(time.Since(now).Seconds()))
		c.Metrics.ConditionFailures.Set(float64(totalFailures))
	}
}

func evalCondition(env Environment, cond Condition) (msg string, severity Severity) {
	defer func() {
		if err := recover(); err != nil {
			msg = fmt.Sprintf("panic: %s", err)
			severity = Debug
		}
	}()
	return cond.Evaluator(env)
}

type event struct {
	Event    ipa_sys.SystemStatusEvent `json:"system_status"`
	Time     time.Time                 `json:"time"`
	NodeName string                    `json:"node_name"`
}

func (c *controller) writeStatusUpdate(fileEncoder *json.Encoder, txn statedb.ReadTxn) error {
	var ev event
	ev.Time = time.Now()
	ev.NodeName = types.GetName()
	status := &ipa_sys.SystemStatusUpdate{}
	ev.Event.Event = &ipa_sys.SystemStatusEvent_Status{Status: status}
	ev.Event.Time = timestamppb.New(ev.Time)

	status.ClusterName = types.GetClusterName()
	status.NodeName = types.GetName()
	status.StartedAt = timestamppb.New(c.startedAt)
	status.System = c.controllerParams.SystemID
	status.TotalConditions = uint32(c.Conditions.NumObjects(txn))
	for cond := range c.Conditions.All(txn) {
		if cond.Latest.Severity == OK {
			continue
		}
		status.FailingConditions = append(status.FailingConditions,
			&ipa_sys.FailingCondition{
				ConditionId: string(cond.Condition.ID),
				Message:     cond.Latest.Message,
			})
	}
	return fileEncoder.Encode(&ev)
}

func (c *controller) writeMetadataUpdate(fileEncoder *json.Encoder, txn statedb.ReadTxn, newConditions []ConditionID) error {
	var ev event
	ev.Time = time.Now()
	ev.NodeName = types.GetName()

	var update ipa_sys.SystemMetadataUpdate
	ev.Event.Event = &ipa_sys.SystemStatusEvent_Metadata{Metadata: &update}

	update.System = c.controllerParams.SystemID
	for _, id := range newConditions {
		cond, _, found := c.Conditions.Get(txn, conditionsIndex.Query(id))
		if !found {
			continue
		}
		update.Conditions = append(update.Conditions, cond.Condition.toMetadata())
	}
	return fileEncoder.Encode(&ev)
}
