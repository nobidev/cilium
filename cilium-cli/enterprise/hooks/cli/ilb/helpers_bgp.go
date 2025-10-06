//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import (
	"context"
	"fmt"
	"net"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	k8s "github.com/cilium/cilium/pkg/k8s/slim/k8s/clientset"
)

func getT1NodeIPs(ctx context.Context, k8sCli *k8s.Clientset) ([]string, []string, error) {
	var ipv4 []string
	var ipv6 []string

	nodes, err := k8sCli.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: "service.cilium.io/node in ( t1, t1-t2 )"})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve K8s nodes: %w", err)
	}

	for _, node := range nodes.Items {
		for _, addr := range node.Status.Addresses {
			if addr.Type == corev1.NodeInternalIP {
				ip := net.ParseIP(addr.Address)
				if ip.To4() == nil {
					ipv6 = append(ipv6, addr.Address)
				} else {
					ipv4 = append(ipv4, addr.Address)
				}
			}
		}
	}

	return ipv4, ipv6, nil
}

func (r *lbTestScenario) getBGPNeighborString() string {
	t1NodeIPv4s, t1NodeIPv6s, err := getT1NodeIPs(r.t.Context(), r.k8sCli)
	if err != nil {
		r.t.Failedf("failed to get T1 node ips: %s", err)
	}

	// prefer BGP peering via ipv6 over ipv4 if available
	if r.t.IPv6Enabled() {
		return strings.Join(t1NodeIPv6s, ";")
	}

	return strings.Join(t1NodeIPv4s, ";")
}
