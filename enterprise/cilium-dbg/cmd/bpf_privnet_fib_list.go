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
	bpfPrivNetFIBCmd.AddCommand(bpfPrivNetFIBListCmd)
}

type fibEntry struct {
	NetID   uint16
	Prefix  string
	Nexthop string
	Flags   privnet.FIBFlags
}

var bpfPrivNetFIBListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List private network FIB map entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium-dbg bpf private-network fib list")

		fibMap, err := privnet.OpenPinnedFIBMap(log)
		if err != nil {
			Fatalf("Failed to open FIB map: %s", err)
		}

		fibList := []fibEntry{}
		parseFIB := func(k bpf.MapKey, v bpf.MapValue) {
			key := k.(*privnet.FIBKey)
			val := v.(*privnet.FIBVal)
			fibList = append(fibList, fibEntry{
				NetID:   uint16(key.NetID),
				Prefix:  key.ToPrefix().String(),
				Nexthop: val.ToAddr().String(),
				Flags:   val.Flags,
			})
		}
		if err := fibMap.Map.DumpWithCallback(parseFIB); err != nil {
			Fatalf("Error dumping content of privnet FIB map: %v\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(fibList); err != nil {
				Fatalf("Error getting output of FIB map in JSON: %v\n", err)
			}
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
		fmt.Fprintln(w, "NetID\tPrefix\tNexthop\tFlags")

		for _, fib := range fibList {
			fmt.Fprintf(w, "%#x\t%s\t%s\t%#x\n",
				fib.NetID, fib.Prefix, fib.Nexthop, fib.Flags)
		}

		w.Flush()
	},
}
