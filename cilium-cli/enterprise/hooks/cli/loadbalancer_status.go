// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/cilium-cli/api"
	enterpriseK8s "github.com/cilium/cilium/cilium-cli/enterprise/hooks/k8s"
	"github.com/cilium/cilium/cilium-cli/enterprise/hooks/loadbalancer"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/status"
)

const (
	padding     = 3
	minWidth    = 5
	paddingChar = ' '
)

const (
	Default = "\033[39m"
	Red     = "\033[31m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Green   = "\033[32m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	Reset   = "\033[0m"
)

var relationOutput string

const (
	relationOutputNumbers    = "numbers"
	relationOutputPercentage = "percentage"
)

func GetLoadbalancerStatus(ctx context.Context, k8sClient *k8s.Client, out io.Writer, params loadbalancer.Parameters) error {
	ec, err := enterpriseK8s.NewEnterpriseClient(k8sClient)
	if err != nil {
		return err
	}

	lc := loadbalancer.NewLoadbalancerClient(ec, params)

	lsm, err := lc.GetLoadbalancerStatusModel(ctx)
	if err != nil {
		return fmt.Errorf("failed to get loadbalancer status: %w", err)
	}

	if params.Output == "json" {
		jsonOutput, err := json.Marshal(lsm)
		if err != nil {
			return fmt.Errorf("failed to output JSON: %w", err)
		}

		fmt.Fprintln(out, string(jsonOutput))

		return nil
	}

	summaryTabWriter := tabwriter.NewWriter(out, minWidth, 0, padding, paddingChar, 0)

	fmt.Fprintln(out, "=========")
	fmt.Fprintln(out, "Summary")
	fmt.Fprintln(out, "=========")
	fmt.Fprintln(out, "")

	fmt.Fprintf(summaryTabWriter, "T1 Nodes:\t%d\n", lsm.Summary.NrOfT1Nodes)
	fmt.Fprintf(summaryTabWriter, "T2 Nodes:\t%d\n", lsm.Summary.NrOfT2Nodes)
	fmt.Fprintf(summaryTabWriter, "Services:\t%d\n", lsm.Summary.NrOfServices)
	fmt.Fprintf(summaryTabWriter, "VIPs:\t%d\n", lsm.Summary.NrOfVIPs)

	summaryTabWriter.Flush()

	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "=========")
	fmt.Fprintln(out, "Services")
	fmt.Fprintln(out, "=========")
	fmt.Fprintln(out, "")

	tableTabWriter := tabwriter.NewWriter(out, minWidth, 0, padding, paddingChar, 0)
	fmt.Fprintf(tableTabWriter, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", "Namespace", "Name", Default+"VIP"+Reset, "Port", "Type", "Deployment Mode", Default+"BGP Peers"+Reset, Default+"BGP"+Reset, Default+"T1"+Reset, Default+"HC T1->[T2|B]"+Reset, Default+"T2"+Reset, Default+"HC T2->B"+Reset, Default+"Backendpools"+Reset, Default+"Status"+Reset)
	fmt.Fprintf(tableTabWriter, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", "---------", "----", Default+"---"+Reset, "----", "----", "---------------", Default+"---------"+Reset, Default+"---"+Reset, Default+"--"+Reset, Default+"-------------"+Reset, Default+"--"+Reset, Default+"--------"+Reset, Default+"------------"+Reset, Default+"------"+Reset)
	for _, f := range lsm.Services {
		fmt.Fprintf(tableTabWriter, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", f.Namespace, f.Name, statusText(f.VIP), f.Port, f.Type, statusText(f.DeploymentMode), printSimpleStatusCell(f.BGPPeerStatus), printSimpleStatusCell(f.BGPNodeStatus), printSimpleStatusCell(f.T1NodeStatus), printSimpleStatusCell(f.T1T2HCStatus), printSimpleStatusCell(f.T2NodeStatus), printSimpleStatusCell(f.T2BackendHCStatus), printGroupedStatusCell(f.BackendpoolStatus), getOverallStatus(f.BGPNodeStatus, f.BGPPeerStatus))
	}

	tableTabWriter.Flush()

	return nil
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

			return GetLoadbalancerStatus(ctx, k8sClient, c.OutOrStdout(), params)
		},
	}

	cmd.Flags().StringVarP(&params.ServiceNamespace, "namespace", "m", "", "Filter for service namespace")
	cmd.Flags().StringVarP(&params.ServiceName, "name", "n", "", "Filter for service name")
	cmd.Flags().StringVarP(&params.ServiceVIP, "vip", "v", "", "Filter for service VIP")
	cmd.Flags().UintVarP(&params.ServicePort, "port", "p", 0, "Filter for service port")
	cmd.Flags().StringVarP(&params.ServiceStatus, "status", "s", "", "Filter for service health status")

	cmd.Flags().DurationVar(&params.WaitDuration, "wait-duration", 1*time.Minute, "Maximum time to wait for result, default 1 minute")
	cmd.Flags().StringVarP(&params.Output, "output", "o", status.OutputSummary, "Output format. One of: json, summary")
	cmd.Flags().StringVarP(&relationOutput, "relationOutput", "r", relationOutputNumbers, "Relation output format. One of: numbers, percentage")

	return cmd
}

func printSimpleStatusCell(status loadbalancer.LoadbalancerStatusModelSimpleStatus) string {
	return fmt.Sprintf("%s %s", statusText(status.Status), relationText(status.Status, status.OK, status.Total))
}

func printGroupedStatusCell(status loadbalancer.LoadbalancerStatusModelGroupedStatus) string {
	statusString := ""

	for _, g := range status.Groups {
		statusString += relationText(status.Status, g.OK, g.Total)
	}

	return fmt.Sprintf("%s %s", statusText(status.Status), statusString)
}

func getOverallStatus(bgpRouteStatus loadbalancer.LoadbalancerStatusModelSimpleStatus, bgpPeerStatus loadbalancer.LoadbalancerStatusModelSimpleStatus) string {
	if bgpRouteStatus.Status == "N/A" || bgpPeerStatus.Status == "N/A" {
		return Red + "OFFLINE" + Reset
	}

	if bgpRouteStatus.OK == 0 || bgpPeerStatus.OK == 0 {
		return Red + "OFFLINE" + Reset
	}

	return Green + "ONLINE" + Reset
}

func statusText(statusText string) string {
	switch statusText {
	case "OK":
		return Green + "OK " + Reset
	case "DEG":
		return Yellow + "DEG" + Reset
	case "N/A":
		return Yellow + "N/A" + Reset
	}

	return Default + statusText + Reset
}

func relationText(status string, ok, total int) string {
	if status == "N/A" || status == "" {
		return ""
	}

	if relationOutput == relationOutputPercentage {
		return fmt.Sprintf("[%d%%]", ok*100/total)
	}

	return fmt.Sprintf("[%d/%d]", ok, total)
}
