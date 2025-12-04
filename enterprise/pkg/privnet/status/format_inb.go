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

func (s NodeStatus) formatINBNode() string {
	sb := strings.Builder{}

	sb.WriteString(fmtBar("Network Bridge", fmtHghlt(s.Name), s.nodeStatus(), 100))
	sb.WriteString("\n")

	for _, net := range s.Networks {
		sb.WriteString(net.formatINBNetwork(s.ConnectedClusters, s.Cluster, s.Name))
		sb.WriteString("\n")
	}
	if len(s.Networks) == 0 {
		sb.WriteString(fmtInfo("No Private Networks configured"))
		sb.WriteString("\n")
	}

	return sb.String()
}

func (pn NetworkStatus) formatINBNetwork(connectedClusters []ConnectedCluster, localCluster tables.ClusterName, localNode tables.NodeName) string {
	sb := strings.Builder{}

	sb.WriteString(fmtIndent(pn.inbNetworkStatusLine(98), 2))

	sb.WriteString(fmtIndent(pn.formatSubnets(96), 4))
	sb.WriteString(fmtIndent(pn.formatRoutes(96), 4))

	sum := summarizeConnectedCluster(pn, connectedClusters, localCluster, localNode)
	sb.WriteString(fmtIndent(sum.formatINBEndpointBar(96), 4))
	sb.WriteString("\n")
	sb.WriteString(fmtIndent(sum.formatINBServedNodes(localCluster), 4))

	return sb.String()
}

func (pn NetworkStatus) inbNetworkStatusLine(width int) string {
	errStr := ""
	if len(pn.Errors) > 0 {
		errStr = fmtIndent(fmtErr(strings.Join(pn.Errors, "\n"))+"\n", 4)
	}
	return fmtBar(
		fmt.Sprintf("Network %s", fmtHghlt(pn.Name)), pn.INBStatus.formatInterface(), pn.inbNetworkStatus(),
		width,
	) + errStr
}
func (pn NetworkStatus) inbNetworkStatus() string {
	if pn.INBStatus.Serving {
		return fmtOk("SERVING")
	} else if len(pn.Errors) == 0 {
		return fmtWrn("NOT SERVING")
	} else {
		return fmtErr("DEGRADED")
	}
}
func (inbSt INBStatus) formatInterface() string {
	ifaceStr := "Interface "
	if inbSt.Interface.Name != "" {
		ifaceStr += fmtHghlt(inbSt.Interface.Name) + " state "
		if inbSt.Interface.Error != "" {
			ifaceStr += fmtErr("ERROR")
		} else {
			ifaceStr += fmtOk("UP")
		}
	} else {
		ifaceStr += fmtWrn("Not connected")
	}
	return ifaceStr
}

func (sum connectedEndpointsSummary) formatINBEndpointBar(width int) string {
	return fmtBar(
		fmt.Sprintf("External Endpoints %d", sum.localExtEPs),
		func() string {
			if sum.activeEps > 0 {
				return fmt.Sprintf("Served Endpoints %d", sum.activeEps)
			} else {
				return fmtInfo(fmt.Sprintf("Served Endpoints %d", sum.activeEps))
			}
		}(),
		fmt.Sprintf("Total Endpoints %d", sum.totalEps),
		width)
}

func (sum connectedEndpointsSummary) formatINBServedNodes(localCluster tables.ClusterName) string {

	const title = "Served Nodes"
	sb := strings.Builder{}
	w := tabwriter.NewWriter(&sb, 20, 20, 2, ' ', 0)

	for _, cluster := range slices.Sorted(maps.Keys(sum.clusters)) {
		info := sum.clusters[cluster]
		if cluster == localCluster {
			// Don't show the local cluster. We currently don't serve the local
			// cluster for the INB. Maybe revisit once we have local breakout
			continue
		}

		activeNodeStr := fmt.Sprintf("%s\t%d/%d (%d/%d endpoints)", cluster, info.activeNodes, info.totalNodes, info.activeEps, info.totalEps-info.extEps)
		if info.activeNodes > 0 {
			activeNodeStr = fmtOk(activeNodeStr)
		} else {
			activeNodeStr = fmtInfo(activeNodeStr)
		}
		fmt.Fprint(w, activeNodeStr, "\n")
	}
	w.Flush()
	return fmtIndentTitle(title, sb.String(), 20)
}
