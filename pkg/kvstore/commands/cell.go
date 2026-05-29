// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/kvstore"
)

var Cell = cell.Module(
	"kvstore-commands",
	"KVStore Commands",

	cell.Provide(func(in struct {
		cell.In

		Client kvstore.Client
	},
	) hive.ScriptCmdsOut {
		if !in.Client.IsEnabled() {
			return hive.ScriptCmdsOut{}
		}
		return hive.NewScriptCmds(Commands(in.Client))
	}),
)
