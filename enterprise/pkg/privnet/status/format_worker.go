//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package status

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

func (s NodeStatus) formatWorkerNode() string {
	sb := strings.Builder{}

	sb.WriteString(fmtBar("Node", fmtHghlt(s.Name), s.nodeStatus(), 100))
	sb.WriteString("\n")

	for _, net := range s.Networks {
		sb.WriteString(net.formatWorkerNetwork(s.ConnectedClusters, s.Cluster, s.Name))
		sb.WriteString("\n")
	}
	if len(s.Networks) == 0 {
		sb.WriteString(fmtInfo("No Private Networks configured"))
		sb.WriteString("\n")
	}
	return sb.String()
}

func (net NetworkStatus) formatWorkerNetwork(connectedClusters []ConnectedCluster, localCluster tables.ClusterName, localNode tables.NodeName) string {
	sb := strings.Builder{}

	sb.WriteString(fmtIndent(net.workerNetworkStatusLine(98), 2))

	sb.WriteString(
		fmtIndent(net.formatSubnets(96), 4),
	)
	sb.WriteString(
		fmtIndent(net.formatRoutes(96), 4),
	)
	sum := summarizeConnectedCluster(net, connectedClusters, localCluster, localNode)
	sb.WriteString(fmtIndent(sum.formatWorkerEndpointBar(96), 4))

	sb.WriteString("\n")

	sb.WriteString(fmtIndent(sum.formatWorkerConnectedNodes(localCluster), 4))
	sb.WriteString("\n")

	sb.WriteString(fmtIndent(net.WorkerStatus.formatWorkerConnectedINBs(localCluster, 96), 4))

	return sb.String()
}

func (pn NetworkStatus) workerNetworkStatusLine(width int) string {

	activeINBStr := ""
	if pn.WorkerStatus.ActiveINB != "" {
		activeINBStr = "Active INB  " + fmtOk(pn.WorkerStatus.ActiveINB)
	}
	errStr := ""
	if len(pn.Errors) > 0 {
		errStr = fmtIndent(fmtErr(strings.Join(pn.Errors, "\n"))+"\n", 4)
	}

	return fmtBar(
		fmt.Sprintf("Network %s", fmtHghlt(pn.Name)), activeINBStr, pn.workerNetworkStatus(),
		width,
	) + errStr
}

func (pn NetworkStatus) workerNetworkStatus() string {
	if len(pn.Errors) == 0 {
		return fmtOk("OK")
	} else {
		return fmtErr("DEGRADED")
	}
}

func (sum connectedEndpointsSummary) formatWorkerEndpointBar(width int) string {
	return fmtBar(
		fmt.Sprintf("Local Endpoints %d", sum.localEPs),
		"",
		fmt.Sprintf("Total Endpoints %d", sum.totalEps),
		width)
}

func (sum connectedEndpointsSummary) formatWorkerConnectedNodes(localCluster tables.ClusterName) string {
	const title = "Endpoints"

	sb := strings.Builder{}
	w := tabwriter.NewWriter(&sb, 20, 20, 2, ' ', 0)

	for _, cluster := range slices.SortedFunc(maps.Keys(sum.clusters), sortWithPin(localCluster)) {
		info := sum.clusters[cluster]

		if info.totalEps == 0 && cluster != localCluster {
			continue
		}

		if cluster == localCluster {
			cluster = cluster + " (local)"
		}

		fmt.Fprintf(w, "%s\t%d Endpoints\n", cluster, info.totalEps)
	}
	w.Flush()
	return fmtIndentTitle(title, sb.String(), 20)
}

type connectedINBSummary struct {
	name         tables.ClusterName
	healthyNodes int
	totalNodes   int
	active       bool
}

func (ws WorkerStatus) formatWorkerConnectedINBs(localCluster tables.ClusterName, width int) string {

	summary := map[tables.ClusterName]connectedINBSummary{}

	for _, inbCl := range ws.ConnectedINBClusters {
		for _, inb := range inbCl.INBs {
			info := summary[inbCl.Name]
			info.name = inbCl.Name
			if inbCl.Name == localCluster {
				info.name += "(local)"
			}
			if inb.Healthy {
				info.healthyNodes++
			}
			info.totalNodes++
			info.active = info.active || inb.Active
			summary[inbCl.Name] = info
		}
	}

	inbsStrings := []string{}
	for _, cluster := range slices.SortedFunc(maps.Keys(summary), sortWithPin(localCluster)) {
		inb := summary[cluster]
		activeStr := ""
		if inb.active {
			activeStr = " [active]"
		}
		nodesStr := fmt.Sprintf("%s %d/%d%s", inb.name, inb.healthyNodes, inb.totalNodes, activeStr)
		if inb.healthyNodes == 0 {
			nodesStr = fmtErr(nodesStr)
		} else if inb.active {
			nodesStr = fmtOk(nodesStr)
		}
		inbsStrings = append(inbsStrings, nodesStr)
	}
	res := fmtWrapLineItemsTitle("Connected INBs", inbsStrings, 18, width)
	if len(inbsStrings) == 0 {
		res += fmtInfo("  No connected INBs\n")
	}
	return res
}
