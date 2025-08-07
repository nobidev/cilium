//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package extepspolicy

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

var Cell = cell.Module(
	"enterprise-ext-eps-policy-map",
	"Isovalent external endpoints policy map",

	cell.Config(defaultConfig),

	cell.Provide(
		newWriter,
		newMap,
	),

	cell.ProvidePrivate(
		newTable,
		toEnabled,
	),

	cell.Invoke(
		registerReconciler,
	),
)

type Config struct {
	ExtEpsPolicyMapMax uint32
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Uint32("ext-eps-policy-map-max", def.ExtEpsPolicyMapMax,
		"Maximum number of entries in the external endpoints policy map")
}

var defaultConfig = Config{
	ExtEpsPolicyMapMax: 1 << 16,
}

// enabled is the type to request enabling map creation and reconciliation.
type enabler bool

// enabled is the type representing whether map creation and reconciliation is enabled.
type enabled bool

// Enable allows to enable the creation and reconciliation of the external
// endpoints policy map. The map is enabled if at least one Enable instance
// returns true.
func Enable[T any](fn func(T) bool) cell.Cell {
	return cell.Provide(func(cfg T) (out struct {
		cell.Out
		Enabler enabler `group:"request-enable-ext-eps-policy-map"`
	}) {
		out.Enabler = enabler(fn(cfg))
		return out
	})
}

// toEnabled summarizes the outputs of [Enable] into a single [enabled] value.
func toEnabled(in struct {
	cell.In

	Enablers []enabler `group:"request-enable-ext-eps-policy-map"`
}) (en enabled) {
	for _, enabler := range in.Enablers {
		en = enabled(bool(en) || bool(enabler))
	}
	return en
}
