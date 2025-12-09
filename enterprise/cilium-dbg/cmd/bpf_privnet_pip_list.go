// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/enterprise/pkg/maps/privnet"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
)

func init() {
	bpfPrivNetPIPCmd.AddCommand(bpfPrivNetPIPListCmd)
}

type pipEntry struct {
	Prefix  string
	NetID   uint16
	NetIP   string
	IfIndex uint32
	MAC     string
	Flags   privnet.PIPFlags
}

var bpfPrivNetPIPListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List private network PIP map entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium-dbg bpf private-network pip list")

		pipMap, err := privnet.OpenPinnedPIPMap(log)
		if err != nil {
			Fatalf("Failed to open PIP map: %s", err)
		}

		pipList := []pipEntry{}
		parsePIP := func(k bpf.MapKey, v bpf.MapValue) {
			key := k.(*privnet.PIPKey)
			val := v.(*privnet.PIPVal)
			pipList = append(pipList, pipEntry{
				Prefix:  key.ToPrefix().String(),
				NetID:   uint16(val.NetID),
				NetIP:   val.ToAddr().String(),
				IfIndex: val.IfIndex,
				MAC:     val.MAC.String(),
				Flags:   val.Flags,
			})
		}
		if err := pipMap.Map.DumpWithCallback(parsePIP); err != nil {
			Fatalf("Error dumping content of privnet PIP map: %v\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(pipList); err != nil {
				Fatalf("Error getting output of PIP map in JSON: %v\n", err)
			}
			return
		}
		w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
		fmt.Fprintln(w, "Prefix\tNetID\tNetIP\tIfIndex\tMAC\tFlags")

		for _, pip := range pipList {
			fmt.Fprintf(w, "%s\t%#x\t%s\t%d\t%s\t%#x\n",
				pip.Prefix, pip.NetID, pip.NetIP, pip.IfIndex, pip.MAC, pip.Flags)
		}

		w.Flush()
	},
}
