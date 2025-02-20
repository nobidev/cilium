// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"github.com/spf13/cobra"
)

func newCmdLoadbalancerTestList() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available Loadbalancer tests",
		Long:  "",
		RunE: func(c *cobra.Command, _ []string) error {
			for _, test := range tests {
				c.Println(testName(test))
			}
			return nil
		},
	}

	return cmd
}
