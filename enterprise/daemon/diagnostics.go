//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/pkg/diagnostics"
	"github.com/cilium/cilium/pkg/hive/health"
	healthTypes "github.com/cilium/cilium/pkg/hive/health/types"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/version"
)

var agentDiagnostics = cell.Group(
	// Provide the diagnostics registry and the controller to write diagnostics
	// to status.log.
	diagnostics.NewCell("cilium-agent", version.GetCiliumVersion().Version),

	// Register diagnostic conditions for OSS features.
	cell.Invoke(registerConditions),
)

// The user constants that can be overridden with --diagnostics-constants.
const (
	// keyEndpointRegenMultiplier is the key for setting the threshold for endpoint regeneration latency, e.g.
	// how many times the 24h average latency should the latency be before the condition fails.
	keyEndpointRegenMultiplier = "endpoint_regen_multiplier"
)

func registerConditions(reg *diagnostics.Registry, db *statedb.DB, healthTable statedb.Table[healthTypes.Status]) error {
	return reg.Register(
		diagnostics.Condition{
			ID:          "endpoint_regeneration",
			SubSystem:   "Endpoint",
			Description: "Endpoint regeneration is taking longer than expected",
			Severity:    diagnostics.SeverityDebug,
			Evaluator:   evalEndpointRegeneration,
		},

		diagnostics.Condition{
			ID:          "hive_degraded_modules",
			SubSystem:   "Hive",
			Description: "One or more agent module is reporting degraded status",
			Severity:    diagnostics.SeverityDebug,
			Evaluator:   evalHiveHealth(db, healthTable),
		},
	)
}

func evalEndpointRegeneration(env diagnostics.Environment) (msg string, failed bool) {
	stats, err := env.Histogram(metrics.EndpointRegenerationTimeStats.Opts().ConfigName, map[string]string{metrics.LabelScope: "total", metrics.LabelStatus: "success"})
	if err != nil {
		return err.Error(), true
	}

	// Default to 3x the 24h average as the threshold, but allow override with "endpoint_regen_multiplier" constant.
	multp := env.UserConstant(keyEndpointRegenMultiplier, 3)

	if stats.Avg_24h > 0.0 && stats.Avg_Latest > multp*stats.Avg_24h {
		msg = fmt.Sprintf("current average endpoint regeneration latency %.1fs is >%.1fx the 24 hour average of %.1fs", stats.Avg_Latest, multp, stats.Avg_24h)
		failed = true
		return
	}
	return fmt.Sprintf("%.2fs OK", stats.Avg_Latest), false
}

func evalHiveHealth(db *statedb.DB, healthTable statedb.Table[healthTypes.Status]) diagnostics.Evaluator {
	return func(env diagnostics.Environment) (string, bool) {
		degraded := []string{}
		for status := range healthTable.List(db.ReadTxn(), health.LevelIndex.Query(healthTypes.LevelDegraded)) {
			degraded = append(degraded, status.ID.String())
		}
		if len(degraded) > 0 {
			return "Degraded modules: " + strings.Join(degraded, ", "), true
		}
		return "", false
	}
}
