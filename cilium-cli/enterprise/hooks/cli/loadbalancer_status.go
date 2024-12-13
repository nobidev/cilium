// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/cilium-cli/api"
	enterpriseK8s "github.com/cilium/cilium/cilium-cli/enterprise/hooks/k8s"
	"github.com/cilium/cilium/cilium-cli/enterprise/hooks/loadbalancer"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/status"
)

func GetLoadbalancerStatus(ctx context.Context, k8sClient *k8s.Client, params loadbalancer.Parameters) (*loadbalancer.LoadbalancerStatusModel, error) {
	ec, err := enterpriseK8s.NewEnterpriseClient(k8sClient)
	if err != nil {
		return nil, err
	}

	lc := loadbalancer.NewLoadbalancerClient(ec, params)

	if err := lc.InitNodeAgentPods(ctx); err != nil {
		return nil, fmt.Errorf("failed to fetch Node Agent Pods: %w", err)
	}

	return lc.GetLoadbalancerStatusModel(ctx)
}

func newCmdLoadbalancerStatus() *cobra.Command {
	params := loadbalancer.Parameters{}

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Display Loadbalancer status",
		Long:  "",
		RunE: func(c *cobra.Command, _ []string) error {
			k8sClient, _ := api.GetK8sClientContextValue(c.Context())

			ctx, cancelFn := context.WithTimeout(c.Context(), params.WaitDuration)
			defer cancelFn()

			lsm, err := GetLoadbalancerStatus(ctx, k8sClient, params)
			if err != nil {
				return err
			}

			return lsm.Output(c.OutOrStdout(), params)

		},
	}

	cmd.Flags().StringVarP(&params.ServiceNamespace, "namespace", "m", "", "Filter for service namespace")
	cmd.Flags().StringVarP(&params.ServiceName, "name", "n", "", "Filter for service name")
	cmd.Flags().StringVarP(&params.ServiceVIP, "vip", "v", "", "Filter for service VIP")
	cmd.Flags().UintVarP(&params.ServicePort, "port", "p", 0, "Filter for service port")
	cmd.Flags().StringVarP(&params.ServiceStatus, "status", "s", "", "Filter for service health status")

	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", 1*time.Minute, "Maximum time to wait for result, default 1 minute")
	cmd.Flags().StringVarP(&params.Output, "output", "o", status.OutputSummary, "Output format. One of: json, summary")
	cmd.Flags().StringVarP(&params.RelationOutput, "relationOutput", "r", loadbalancer.RelationOutputNumbers, "Relation output format. One of: numbers, percentage")

	return cmd
}
