//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lb

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/enterprise/pkg/annotation"
	ossannotation "github.com/cilium/cilium/pkg/annotation"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/addressing"
)

func (r *standaloneLbReconciler) desiredService(lb *isovalentv1alpha1.IsovalentLB) *corev1.Service {
	labels := map[string]string{
		"lb.cilium.io/tier": "t1",
	}

	annotations := map[string]string{}

	// LB IPAM
	annotations[ossannotation.LBIPAMIPsKey] = lb.Spec.VIP

	// Support different LB frontends having the same VIP but a different port
	// For the sake of simplicity, the VIP itself is used as sharing key
	annotations[ossannotation.LBIPAMSharingKey] = lb.Spec.VIP
	annotations[ossannotation.LBIPAMSharingAcrossNamespace] = "*"

	// BGP
	annotations[annotation.ServiceHealthBGPAdvertiseThreshold] = "1"

	// T1 -> T2 health checking
	annotations[annotation.ServiceHealthHTTPPath] = healthCheckHttpPath
	annotations[annotation.ServiceHealthHTTPMethod] = healthCheckHttpMethod
	annotations[annotation.ServiceHealthProbeInterval] = lb.Spec.Healthcheck.Interval
	annotations[annotation.ServiceHealthProbeTimeout] = "5s"
	annotations[annotation.ServiceHealthThresholdHealthy] = "2"
	annotations[annotation.ServiceHealthThresholdUnhealthy] = "2"
	annotations[annotation.ServiceHealthQuarantineTimeout] = "30s"

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   lb.Namespace,
			Name:        lb.Name,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: "TCP",
					Port:     lb.Spec.Port,
				},
			},
		},
	}
}

func (r *standaloneLbReconciler) desiredEndpoints(ctx context.Context, lb *isovalentv1alpha1.IsovalentLB) (*corev1.Endpoints, error) {
	t2NodeIPs, err := r.getT2NodeAddresses(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve T2 node ips: %w", err)
	}
	epAddresses := []corev1.EndpointAddress{}
	for _, addr := range t2NodeIPs {
		epAddresses = append(epAddresses, corev1.EndpointAddress{IP: addr})
	}

	return &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: lb.Namespace,
			Name:      lb.Name,
		},
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: epAddresses,
				Ports: []corev1.EndpointPort{
					{
						Name:     "http",
						Port:     80,
						Protocol: "TCP",
					},
				},
			},
		},
	}, nil
}

func (r *standaloneLbReconciler) getT2NodeAddresses(ctx context.Context) ([]string, error) {
	nodeStore, err := r.nodeSource.Store(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get node store: %w", err)
	}

	t2NodeIPs := []string{}

	allNodes := nodeStore.List()
	for _, cn := range allNodes {
		if v := cn.Labels["lb.cilium.io/tier"]; v == "t2" {
			var nodeIP string
			for _, addr := range cn.Spec.Addresses {
				if addr.Type == addressing.NodeInternalIP {
					nodeIP = addr.IP
					break
				}
			}
			if nodeIP == "" {
				r.logger.
					WithField(logfields.Resource, cn.Name).
					Warn("Could not find InternalIP for tier 2 CiliumNode")
				continue
			}
			t2NodeIPs = append(t2NodeIPs, nodeIP)
		}
	}

	return t2NodeIPs, nil
}
