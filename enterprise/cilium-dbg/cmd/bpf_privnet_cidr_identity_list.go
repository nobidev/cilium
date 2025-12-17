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
	bpfPrivNetCIDRIdentityCmd.AddCommand(bpfPrivNetCIDRIdentityListCmd)
}

type cidrIdentityEntry struct {
	Prefix   string
	Identity uint32
}

var bpfPrivNetCIDRIdentityListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List private network CIDR identity map entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium-dbg bpf private-network cidr-identity list")

		cidrIdentityMap, err := privnet.OpenPrivNetCIDRIdentityMap(log)
		if err != nil {
			Fatalf("Failed to open CIDR identity map: %s", err)
		}

		cidrIdentityList := []cidrIdentityEntry{}
		parseEntry := func(k bpf.MapKey, v bpf.MapValue) {
			key := k.(*privnet.CIDRIdentityKey)
			val := v.(*privnet.CIDRIdentityVal)
			cidrIdentityList = append(cidrIdentityList, cidrIdentityEntry{
				Prefix:   key.String(),
				Identity: val.SecIdentity,
			})
		}
		if err := cidrIdentityMap.Map.DumpWithCallback(parseEntry); err != nil {
			Fatalf("Error dumping content of privnet CIDR identity map: %v\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(cidrIdentityList); err != nil {
				Fatalf("Error getting output of CIDR identity map in JSON: %v\n", err)
			}
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
		fmt.Fprintln(w, "Prefix\tIdentity")

		for _, c := range cidrIdentityList {
			fmt.Fprintf(w, "%s\t%d\n", c.Prefix, c.Identity)
		}

		w.Flush()
	},
}
