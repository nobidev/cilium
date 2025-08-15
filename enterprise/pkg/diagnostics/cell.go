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
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	ipa_sys "github.com/isovalent/ipa/system_status/v1alpha"

	"github.com/cilium/cilium/pkg/metrics"
)

// NewCell creates a cell that provides the diagnostics [Registry] for
// registering diagnostic conditions.  The registered conditions are evaluated
// periodically with results stored in the 'diagnostics' table and written
// out to log file that is sent to Hubble Timescape.
//
// The export format is defined as protobuf in github.com/isovalent/ipa/systemstatus.
//
// To inspect the current evaluation (in cilium-dbg shell): "db/show diagnostics"
func NewCell(systemName string, systemVersion string) cell.Cell {
	return cell.Module(
		"diagnostics",
		"System diagnostics",

		cell.Config(DefaultConfig),

		cell.Provide(
			NewRegistry,
			statedb.RWTable[ConditionStatus].ToTable,
			newInternalConditions,
			newController,
		),

		metrics.Metric(newMetrics),

		cell.ProvidePrivate(
			NewConditionsTable,
			func() *ipa_sys.SystemID {
				return &ipa_sys.SystemID{
					Name:    systemName,
					Version: systemVersion,
				}
			},
		),
	)
}
