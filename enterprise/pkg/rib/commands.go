//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package rib

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/hive"
	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"
)

// ribReadCommands provides the commands to read the RIB
func ribReadCommands(r *RIB) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"rib/list": ribListCommand(r),
	})
}

func ribListCommand(r *RIB) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "List RIB entries",
			Detail: []string{
				"To show routes in the specific VRF: 'rib/list --vrf 123'",
			},
			Flags: func(fs *pflag.FlagSet) {
				fs.String("vrf", "all", "VRF ID to show, or 'all' for all VRFs")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			vrf, err := s.Flags.GetString("vrf")
			if err != nil {
				return nil, err
			}
			return func(*script.State) (stdout, stderr string, err error) {
				filter := func(vrfID uint32) bool { return true }
				if vrf != "all" {
					vrfID64, err := strconv.ParseUint(vrf, 10, 32)
					if err != nil {
						return "", "", fmt.Errorf("invalid vrfID %q: %w", vrf, err)
					}
					filter = func(vrfID uint32) bool {
						return vrfID == uint32(vrfID64)
					}
				}

				b := &strings.Builder{}
				tw := tabwriter.NewWriter(b, 4, 0, 4, ' ', 0)

				fmt.Fprintf(tw, "Best\tVRF\tPrefix\tOwner\tProtocol\tNextHop\n")

				r.forEach(func(vrfID uint32, p netip.Prefix, d *Destination) bool {
					for _, r := range d.routes {
						if !filter(vrfID) {
							continue
						}
						bestSymbol := " "
						if r.Equal(d.best) {
							bestSymbol = "*"
						}
						fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\n",
							bestSymbol,
							vrfID,
							r.Prefix,
							r.Owner,
							r.Protocol,
							r.NextHop,
						)
					}
					return true
				})

				tw.Flush()

				return b.String(), "", nil
			}, nil
		},
	)
}
