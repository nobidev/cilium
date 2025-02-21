// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"github.com/spf13/cobra"

	ilbCli "github.com/cilium/cilium/cilium-cli/enterprise/hooks/cli/ilb"
)

func newCmdLoadbalancerTestList() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available Loadbalancer tests",
		Long:  "",
		RunE: func(c *cobra.Command, _ []string) error {
			for _, test := range ilbCli.Tests {
				tf := ilbCli.NewLBTestFunc(nil, c.Context(), test)
				c.Println(tf.Name())
			}
			return nil
		},
	}

	return cmd
}
