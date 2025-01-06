// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/cilium-cli/api"
	"github.com/cilium/cilium/cilium-cli/status"
	loadbalancerStatus "github.com/cilium/cilium/enterprise/pkg/lb/status"
)

func newCmdServiceStatus() *cobra.Command {
	params := loadbalancerStatus.Parameters{}

	cmd := &cobra.Command{
		Use:   "service <name>",
		Args:  cobra.ExactArgs(1),
		Short: "Display service status",
		Long:  "",
		RunE: func(c *cobra.Command, args []string) error {
			k8sClient, _ := api.GetK8sClientContextValue(c.Context())

			ctx, cancelFn := context.WithTimeout(c.Context(), params.WaitDuration)
			defer cancelFn()

			params.ServiceName = args[0]
			params.Verbose = true

			lsm, err := GetLoadbalancerStatus(ctx, k8sClient, params)
			if err != nil {
				return err
			}

			if len(lsm.Services) == 0 {
				return fmt.Errorf("no service found with %q name", params.ServiceName)
			}

			return lsm.Output(c.OutOrStdout(), params)

		},
	}

	cmd.Flags().StringVarP(&params.ServiceNamespace, "namespace", "n", "", "Filter for service namespace")

	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", 1*time.Minute, "Maximum time to wait for result, default 1 minute")
	cmd.Flags().StringVarP(&params.Output, "output", "o", status.OutputSummary, "Output format. One of: json, summary")
	cmd.Flags().StringVarP(&params.RelationOutput, "relationOutput", "r", loadbalancerStatus.RelationOutputNumbers, "Relation output format. One of: numbers, percentage")

	cmd.Flags().BoolVarP(&params.Colors, "colors", "c", true, "Enable colors in 'summary' output")

	return cmd
}
