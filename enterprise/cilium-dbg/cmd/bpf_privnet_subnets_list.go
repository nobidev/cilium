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
	"net/netip"
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
	bpfPrivNetSubnetsCmd.AddCommand(bpfPrivNetSubnetsListCmd)
}

type subnetEntry struct {
	NetID    uint16
	Prefix   netip.Prefix
	SubnetID uint16
}

var bpfPrivNetSubnetsListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List private network subnets map entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium-dbg bpf private-network subnets list")

		subnetsMap, err := privnet.OpenPinnedSubnetsMap(log)
		if err != nil {
			Fatalf("Failed to open privnet_subnets map: %s", err)
		}

		var subnets []subnetEntry
		parseSubnets := func(k bpf.MapKey, v bpf.MapValue) {
			key := k.(*privnet.SubnetKey)
			val := v.(*privnet.SubnetVal)
			subnets = append(subnets, subnetEntry{
				NetID:    uint16(key.NetID),
				Prefix:   key.ToPrefix(),
				SubnetID: uint16(val.SubnetID),
			})
		}
		if err := subnetsMap.Map.DumpWithCallback(parseSubnets); err != nil {
			Fatalf("Error dumping content of privnet_subnets map: %v", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(subnets); err != nil {
				Fatalf("Error getting output of privnet_subnets map in JSON: %v", err)
			}
			return
		}
		w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
		fmt.Fprintln(w, "NetID\tPrefix\tSubnetID")

		for _, subnet := range slices.SortedFunc(
			slices.Values(subnets),
			func(a, b subnetEntry) int {
				return cmp.Or(cmp.Compare(a.NetID, b.NetID), a.Prefix.Addr().Compare(b.Prefix.Addr()))
			}) {
			fmt.Fprintf(w, "%#x\t%s\t%#x\n",
				subnet.NetID, subnet.Prefix, subnet.SubnetID)
		}

		w.Flush()
	},
}
