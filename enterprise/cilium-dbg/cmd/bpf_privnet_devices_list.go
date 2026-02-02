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
	"cmp"
	"fmt"
	"os"
	"slices"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/enterprise/pkg/maps/privnet"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
)

func init() {
	bpfPrivNetDevicesCmd.AddCommand(bpfPrivNetDevicesListCmd)
}

type devEntry struct {
	IfIndex uint32
	NetID   uint16
}

var bpfPrivNetDevicesListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List private network devices map entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium-dbg bpf private-network devices list")

		devicesMap, err := privnet.OpenPinnedDevicesMap(log)
		if err != nil {
			Fatalf("Failed to open privnet_devices map: %s", err)
		}

		var devs []devEntry
		parseDevs := func(k bpf.MapKey, v bpf.MapValue) {
			key := k.(*privnet.DeviceKey)
			val := v.(*privnet.DeviceVal)
			devs = append(devs, devEntry{
				IfIndex: key.IfIndex,
				NetID:   uint16(val.NetworkID),
			})
		}
		if err := devicesMap.Map.DumpWithCallback(parseDevs); err != nil {
			Fatalf("Error dumping content of privnet_devices map: %v", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(devs); err != nil {
				Fatalf("Error getting output of privnet_devices map in JSON: %v", err)
			}
			return
		}
		w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
		fmt.Fprintln(w, "IfIndex\tNetID")

		for _, dev := range slices.SortedFunc(
			slices.Values(devs),
			func(a, b devEntry) int {
				return cmp.Compare(a.IfIndex, b.IfIndex)
			}) {
			fmt.Fprintf(w, "%d\t%#x\n",
				dev.IfIndex, dev.NetID)
		}

		w.Flush()
	},
}
