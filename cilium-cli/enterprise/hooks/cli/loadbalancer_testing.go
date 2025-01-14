// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"github.com/spf13/cobra"
)

func newCmdLoadbalancerTest() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Run Loadbalancer tests",
		Long:  "",
		RunE: func(c *cobra.Command, _ []string) error {
			return nil

		},
	}

	return cmd
}
