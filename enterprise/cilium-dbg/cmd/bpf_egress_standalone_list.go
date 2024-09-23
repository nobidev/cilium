//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/enterprise/pkg/maps/egressmapha"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/logging"
)

type segwEntry struct {
	EndpointIP       string
	TunnelEndpoint   string
	SecurityIdentity uint32
}

var bpfEgressStandaloneListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List standalone egress gateway entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf egress standalone list")

		segwMap, err := egressmapha.OpenPinnedSEGWMap(logging.DefaultSlogLogger)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				Fatalf("Cannot find standalone egress gateway bpf map")
			}

			Fatalf("Cannot open standalone egress gateway bpf map: %s", err)
		}

		entries := []segwEntry{}
		parse := func(key *egressmapha.SEGWMapKey4, val *egressmapha.SEGWMapVal4) {
			entries = append(entries, segwEntry{
				EndpointIP:       key.EndpointIP.String(),
				TunnelEndpoint:   val.TunnelEndpoint.String(),
				SecurityIdentity: val.SecurityIdentity,
			})
		}

		if err := segwMap.IterateWithCallback(parse); err != nil {
			Fatalf("Error dumping content of standalone egress gateway map: %s\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(entries); err != nil {
				Fatalf("Error getting output of map in JSON: %s\n", err)
			}
			return
		}

		if len(entries) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
		} else {
			printSEGWList(entries)
		}
	},
}

func printSEGWList(entries []segwEntry) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	fmt.Fprintln(w, "Endpoint IP\tTunnel Endpoint\tSecurity Identity")

	for _, entry := range entries {
		fmt.Fprintf(w, "%s\t%s\t%d\n", entry.EndpointIP, entry.TunnelEndpoint, entry.SecurityIdentity)
	}

	w.Flush()
}

func init() {
	bpfEgressStandaloneCmd.AddCommand(bpfEgressStandaloneListCmd)
	command.AddOutputOption(bpfEgressStandaloneListCmd)
}
