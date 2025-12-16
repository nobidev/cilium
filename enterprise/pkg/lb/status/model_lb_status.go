// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
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
	Bold    = "\033[1m"
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

	if !params.Colors {
		Default = ""
		Red = ""
		Yellow = ""
		Blue = ""
		Green = ""
		Magenta = ""
		Cyan = ""
		Bold = ""
		Reset = ""
	}

	if !params.Verbose {

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

	}

	tableTabWriter := tabwriter.NewWriter(out, minWidth, 0, padding, paddingChar, 0)
	fmt.Fprintf(tableTabWriter, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", "Namespace", "Name", Default+"VIP"+Reset, "Port", "Type", Default+"D-Mode"+Reset, Default+"BGP Peers"+Reset, Default+"BGP Routes"+Reset, Default+"T1"+Reset, Default+"HC T1->[T2|B]"+Reset, Default+"T2"+Reset, Default+"HC T2->B"+Reset, Default+"Backendpools"+Reset, Default+"Status"+Reset)
	fmt.Fprintf(tableTabWriter, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", "---------", "----", Default+"---"+Reset, "----", "----", Default+"------"+Reset, Default+"---------"+Reset, Default+"----------"+Reset, Default+"--"+Reset, Default+"-------------"+Reset, Default+"--"+Reset, Default+"--------"+Reset, Default+"------------"+Reset, Default+"------"+Reset)
	for _, f := range lsm.Services {
		fmt.Fprintf(tableTabWriter, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", f.Namespace, f.Name, statusText(f.VIP), f.Port, f.Type,
			statusText(f.DeploymentMode),
			printSimpleStatusCell(f.BGPPeerStatus.LoadbalancerStatusModelSimpleStatus, params.RelationOutput),
			printSimpleStatusCell(f.BGPRouteStatus, params.RelationOutput),
			printSimpleStatusCell(f.T1NodeStatus, params.RelationOutput),
			printSimpleStatusCell(f.T1T2HCStatus.LoadbalancerStatusModelSimpleStatus, params.RelationOutput),
			printSimpleStatusCell(f.T2NodeStatus, params.RelationOutput),
			printSimpleStatusCell(f.T2BackendHCStatus.LoadbalancerStatusModelSimpleStatus, params.RelationOutput),
			printGroupedStatusCell(f.BackendpoolStatus, params.RelationOutput),
			getOverallStatus(f.BGPRouteStatus, f.BGPPeerStatus.LoadbalancerStatusModelSimpleStatus))
	}

	tableTabWriter.Flush()

	if !params.Verbose {
		return nil
	}

	verboseTabWriter := tabwriter.NewWriter(out, minWidth, 0, padding, paddingChar, 0)

	fmt.Fprintln(out, "")

	fmt.Fprintln(verboseTabWriter, Bold+"BGP Peers"+Reset)
	fmt.Fprintln(verboseTabWriter, Bold+"---------"+Reset)
	for _, p := range lsm.Services[0].BGPPeerStatus.Peers {
		fmt.Fprintf(verboseTabWriter, "%s(%s)\n", p.Name, statusTextFromBool(p.IsHealthy))
	}
	fmt.Fprintln(verboseTabWriter)

	fmt.Fprintln(verboseTabWriter, Bold+"HC T1->[T2|B]"+Reset)
	fmt.Fprintln(verboseTabWriter, Bold+"-------------"+Reset)
	hcByFrom := hcsByFrom(lsm.Services[0].T1T2HCStatus.HealthChecks)
	for from, hc := range hcByFrom {
		fmt.Fprintf(verboseTabWriter, "%s:", from)
		for _, h := range hc {
			fmt.Fprintf(verboseTabWriter, "\t%s(%s)\n", h.Endpoint, statusTextFromBool(h.IsHealthy))
		}
	}
	fmt.Fprintln(verboseTabWriter)

	fmt.Fprintln(verboseTabWriter, Bold+"HC T2->B"+Reset)
	fmt.Fprintln(verboseTabWriter, Bold+"--------"+Reset)
	hcByFrom = hcsByFrom(lsm.Services[0].T2BackendHCStatus.HealthChecks)
	for from, hc := range hcByFrom {
		fmt.Fprintf(verboseTabWriter, "%s:", from)
		for _, h := range hc {
			fmt.Fprintf(verboseTabWriter, "\t%s(%s)\n", h.Endpoint, statusTextFromBool(h.IsHealthy))
		}
	}
	fmt.Fprintln(verboseTabWriter)

	verboseTabWriter.Flush()

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
	BGPPeerStatus     BGPPeerStatus                        `json:"bgpPeerStatus"`
	BGPRouteStatus    LoadbalancerStatusModelSimpleStatus  `json:"bgpRouteStatus"`
	T1NodeStatus      LoadbalancerStatusModelSimpleStatus  `json:"t1NodeStatus"`
	T1T2HCStatus      HealthChecksStatus                   `json:"t1t2HealthcheckStatus"`
	T2NodeStatus      LoadbalancerStatusModelSimpleStatus  `json:"t2NodeStatus"`
	T2BackendHCStatus HealthChecksStatus                   `json:"t2BackendHealthcheckStatus"`
	BackendpoolStatus LoadbalancerStatusModelGroupedStatus `json:"backendpoolStatus"`
	Status            string                               `json:"status"`
}

type LoadbalancerStatusModelSimpleStatus struct {
	Status string `json:"status"`
	OK     int    `json:"ok"`
	Total  int    `json:"total"`
}

type BGPPeer struct {
	Name      string `json:"name"` // ip-asn
	IsHealthy bool   `json:"healthy"`
}

type BGPPeerStatus struct {
	LoadbalancerStatusModelSimpleStatus

	Peers []BGPPeer `json:"peers"`
}

type LoadbalancerStatusModelGroupedStatus struct {
	Status string                                `json:"status"`
	Groups []LoadbalancerStatusModelSimpleStatus `json:"groups"`
}

type HCStatus struct {
	From      string `json:"from"`
	Endpoint  string `json:"endpoint"`
	IsHealthy bool   `json:"healthy"`
}

type HealthChecksStatus struct {
	LoadbalancerStatusModelSimpleStatus

	HealthChecks []HCStatus `json:"endpoints"`
}

func printSimpleStatusCell(status LoadbalancerStatusModelSimpleStatus, rel string) string {
	return fmt.Sprintf("%s %s", statusText(status.Status), relationText(status.Status, status.OK, status.Total, rel))
}

func printGroupedStatusCell(status LoadbalancerStatusModelGroupedStatus, rel string) string {
	statusString := strings.Builder{}

	for _, g := range status.Groups {
		statusString.WriteString(relationText(status.Status, g.OK, g.Total, rel))
	}

	return fmt.Sprintf("%s %s", statusText(status.Status), statusString.String())
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

func statusTextFromBool(ok bool) string {
	if ok {
		return Green + "OK" + Reset
	}

	return Yellow + "DEG" + Reset
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

func hcsByFrom(hcs []HCStatus) map[string][]HCStatus {
	hcByFrom := map[string][]HCStatus{}

	for _, hc := range hcs {
		if _, ok := hcByFrom[hc.From]; !ok {
			hcByFrom[hc.From] = []HCStatus{}
		}
		hcByFrom[hc.From] = append(hcByFrom[hc.From], hc)
	}

	return hcByFrom
}
