// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
)

const (
	padding     = 3
	minWidth    = 5
	paddingChar = ' '
)

var (
	Default = "\033[39m"
	Red     = "\033[31m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Green   = "\033[32m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	Reset   = "\033[0m"
)

const (
	RelationOutputNumbers    = "numbers"
	RelationOutputPercentage = "percentage"
)

type LoadbalancerStatusModel struct {
	Summary  LoadbalancerStatusModelSummary   `json:"summary,omitempty"`
	Services []LoadbalancerStatusModelService `json:"services,omitempty"`
}

func (lsm *LoadbalancerStatusModel) Output(out io.Writer, params Parameters) error {
	if params.Output == "json" {
		jsonOutput, err := json.Marshal(lsm)
		if err != nil {
			return fmt.Errorf("failed to output JSON: %w", err)
		}

		fmt.Fprintln(out, string(jsonOutput))

		return nil
	}

	if params.NoColors {
		Default = ""
		Red = ""
		Yellow = ""
		Blue = ""
		Green = ""
		Magenta = ""
		Cyan = ""
		Reset = ""
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
	fmt.Fprintf(tableTabWriter, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", "Namespace", "Name", Default+"VIP"+Reset, "Port", "Type", Default+"D-Mode"+Reset, Default+"BGP Peers"+Reset, Default+"BGP"+Reset, Default+"T1"+Reset, Default+"HC T1->[T2|B]"+Reset, Default+"T2"+Reset, Default+"HC T2->B"+Reset, Default+"Backendpools"+Reset, Default+"Status"+Reset)
	fmt.Fprintf(tableTabWriter, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", "---------", "----", Default+"---"+Reset, "----", "----", Default+"------"+Reset, Default+"---------"+Reset, Default+"---"+Reset, Default+"--"+Reset, Default+"-------------"+Reset, Default+"--"+Reset, Default+"--------"+Reset, Default+"------------"+Reset, Default+"------"+Reset)
	for _, f := range lsm.Services {
		fmt.Fprintf(tableTabWriter, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", f.Namespace, f.Name, statusText(f.VIP), f.Port, f.Type,
			statusText(f.DeploymentMode),
			printSimpleStatusCell(f.BGPPeerStatus, params.RelationOutput),
			printSimpleStatusCell(f.BGPNodeStatus, params.RelationOutput),
			printSimpleStatusCell(f.T1NodeStatus, params.RelationOutput),
			printSimpleStatusCell(f.T1T2HCStatus, params.RelationOutput),
			printSimpleStatusCell(f.T2NodeStatus, params.RelationOutput),
			printSimpleStatusCell(f.T2BackendHCStatus, params.RelationOutput),
			printGroupedStatusCell(f.BackendpoolStatus, params.RelationOutput),
			getOverallStatus(f.BGPNodeStatus, f.BGPPeerStatus))
	}

	tableTabWriter.Flush()

	return nil
}

type LoadbalancerStatusModelSummary struct {
	NrOfT1Nodes  int `json:"nrOfT1Nodes"`
	NrOfT2Nodes  int `json:"nrOfT2Nodes"`
	NrOfServices int `json:"nrOfServices"`
	NrOfVIPs     int `json:"nrOfVips"`
}

type LoadbalancerStatusModelService struct {
	Namespace         string                               `json:"namespace"`
	Name              string                               `json:"name"`
	VIP               string                               `json:"vip"`
	Port              uint                                 `json:"port"`
	Type              string                               `json:"type"`
	DeploymentMode    string                               `json:"deploymentMode"`
	BGPPeerStatus     LoadbalancerStatusModelSimpleStatus  `json:"bgpPeerStatus"`
	BGPNodeStatus     LoadbalancerStatusModelSimpleStatus  `json:"bgpNodeStatus"`
	T1NodeStatus      LoadbalancerStatusModelSimpleStatus  `json:"t1NodeStatus"`
	T1T2HCStatus      LoadbalancerStatusModelSimpleStatus  `json:"t1t2HealthcheckStatus"`
	T2NodeStatus      LoadbalancerStatusModelSimpleStatus  `json:"t2NodeStatus"`
	T2BackendHCStatus LoadbalancerStatusModelSimpleStatus  `json:"t2BackendHealthcheckStatus"`
	BackendpoolStatus LoadbalancerStatusModelGroupedStatus `json:"backendpoolStatus"`
	Status            string                               `json:"status"`
}

type LoadbalancerStatusModelSimpleStatus struct {
	Status string `json:"status"`
	OK     int    `json:"ok"`
	Total  int    `json:"total"`
}

type LoadbalancerStatusModelGroupedStatus struct {
	Status string                                `json:"status"`
	Groups []LoadbalancerStatusModelSimpleStatus `json:"groups"`
}

func printSimpleStatusCell(status LoadbalancerStatusModelSimpleStatus, rel string) string {
	return fmt.Sprintf("%s %s", statusText(status.Status), relationText(status.Status, status.OK, status.Total, rel))
}

func printGroupedStatusCell(status LoadbalancerStatusModelGroupedStatus, rel string) string {
	statusString := ""

	for _, g := range status.Groups {
		statusString += relationText(status.Status, g.OK, g.Total, rel)
	}

	return fmt.Sprintf("%s %s", statusText(status.Status), statusString)
}

func getOverallStatus(bgpRouteStatus LoadbalancerStatusModelSimpleStatus, bgpPeerStatus LoadbalancerStatusModelSimpleStatus) string {
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

func relationText(status string, ok, total int, relationOutput string) string {
	if status == "N/A" || status == "" {
		return ""
	}

	if relationOutput == RelationOutputPercentage {
		return fmt.Sprintf("[%d%%]", ok*100/total)
	}

	return fmt.Sprintf("[%d/%d]", ok, total)
}
