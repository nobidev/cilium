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
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	k8s "github.com/cilium/cilium/pkg/k8s/slim/k8s/clientset"
)

func getT1NodeIPs(k8sCli *k8s.Clientset) ([]string, error) {
	var ips []string

	nodes, err := k8sCli.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{LabelSelector: "service.cilium.io/node=t1"})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve K8s nodes: %w", err)
	}

	for _, node := range nodes.Items {
		ip := ""
		for _, addrs := range node.Status.Addresses {
			// prefer InternalIP
			if ip == "" && addrs.Type == corev1.NodeExternalIP {
				ip = addrs.Address
			} else if addrs.Type == corev1.NodeInternalIP {
				ip = addrs.Address
			}
		}

		if ip == "" {
			return nil, fmt.Errorf("node %s does not have any IP addr", node.ObjectMeta.Name)
		}

		ips = append(ips, ip)
	}

	return ips, nil
}

func getBGPNeighborString(k8sCli *k8s.Clientset) string {
	t1NodeIPs, err := getT1NodeIPs(k8sCli)
	if err != nil {
		fatalf("failed to get T1 node ips: %s", err)
	}

	return strings.Join(t1NodeIPs, ";")
}
