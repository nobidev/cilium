//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package collector

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/status"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	nomgr "github.com/cilium/cilium/pkg/node/manager"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb"
)

var Cell = cell.Group(
	cell.Provide(newCmd),
)

func newCmd(in struct {
	cell.In

	Config      config.Config
	ClusterInfo cmtypes.ClusterInfo

	DB              *statedb.DB
	PrivateNetworks statedb.Table[tables.PrivateNetwork]
	Endpoints       statedb.Table[tables.Endpoint]
	MapEntries      statedb.Table[*tables.MapEntry]
	ActiveNetworks  statedb.Table[tables.ActiveNetwork]
	INBs            statedb.Table[tables.INB]

	NM nomgr.NodeManager
}) hive.ScriptCmdsOut {
	sc := &statusCollector{
		config:          in.Config,
		db:              in.DB,
		privateNetworks: in.PrivateNetworks,
		endpoints:       in.Endpoints,
		mapEntries:      in.MapEntries,
		clusterInfo:     in.ClusterInfo,
		activeNetworks:  in.ActiveNetworks,
		inbs:            in.INBs,
		nm:              in.NM,
	}
	return hive.NewScriptCmds(
		map[string]script.Cmd{
			"privnet/status": statusCmd(sc),
		},
	)
}

func statusCmd(sc *statusCollector) script.Cmd {
	return script.Command(script.CmdUsage{
		Summary: "Get summary of private network status",
		Flags: func(fs *pflag.FlagSet) {
			fs.StringP("output", "o", "plain", "Output format. One of: (plain, json)")
			fs.BoolP("color", "c", true, "Whether to color the output. (Only applies to 'plain' output format)")
		},
	}, func(s *script.State, args ...string) (script.WaitFunc, error) {

		return func(*script.State) (stdout, stderr string, err error) {
			stat := sc.collectNodeStatus()

			format, err := s.Flags.GetString("output")
			if err != nil {
				return "", "", err
			}
			color, err := s.Flags.GetBool("color")
			if err != nil {
				return "", "", err
			}

			switch format {
			case "json":
				out, err := json.MarshalIndent(stat, "", "  ")
				if err != nil {
					return "", "", fmt.Errorf("json.Marshal: %w", err)
				}
				return string(out) + "\n", "", nil
			case "plain":
				out := stat.Format()
				if !color {
					out = status.FmtReset(out)
				}
				return out, "", nil
			default:
				return "", "", fmt.Errorf("Unknown output format %q", format)
			}
		}, nil
	})
}
