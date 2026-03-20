// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"github.com/spf13/cobra"
)

func NewCmdLoadbalancer() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "loadbalancer",
		Short:   "Access to Loadbalancer control plane",
		Long:    ``,
		Aliases: []string{"lb"},
		Hidden:  true,
	}

	cmd.AddCommand(newCmdLoadbalancerStatus())
	cmd.AddCommand(newCmdLoadbalancerTest())
	cmd.AddCommand(newCmdServiceStatus())
	cmd.AddCommand(newCmdLoadbalancerT2ApplicationlogStreamer())
	cmd.AddCommand(newCmdLoadbalancerT2AccesslogStreamer())
	cmd.AddCommand(NewCmdK8sBackend())

	return cmd
}

func ciliumNamespace(cmd *cobra.Command) string {
	parentCmd := cmd
	for parentCmd.Parent() != nil {
		parentCmd = parentCmd.Parent()
	}
	return parentCmd.Flag("namespace").Value.String()
}
