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
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/addressing"
)

func (r *lbFrontendReconciler) desiredService(model *lbFrontend) *corev1.Service {
	labels := map[string]string{
		"lb.cilium.io/tier": "t1",
	}

	annotations := map[string]string{}

	// LB IPAM
	if model.staticIP != nil {
		annotations[ossannotation.LBIPAMIPsKey] = *model.staticIP

		// Support different LB frontends having the same VIP but a different port
		// For the sake of simplicity, the VIP itself is used as sharing key
		annotations[ossannotation.LBIPAMSharingKey] = *model.staticIP
		annotations[ossannotation.LBIPAMSharingAcrossNamespace] = "*"
	}

	// TODO: should the following config be part of the lbFrontend model? (infra?)

	// BGP
	annotations[annotation.ServiceHealthBGPAdvertiseThreshold] = "1"

	// T1 -> T2 health checking
	annotations[annotation.ServiceHealthHTTPPath] = healthCheckHttpPath
	annotations[annotation.ServiceHealthHTTPMethod] = healthCheckHttpMethod
	annotations[annotation.ServiceHealthProbeInterval] = "5s" // TODO: evaluate interval based on all backend healtcheck intervals?
	annotations[annotation.ServiceHealthProbeTimeout] = "5s"
	annotations[annotation.ServiceHealthThresholdHealthy] = "2" // TODO: set threshold to 1 (healthy & unhealthy) as we want to directly use it once T2 flips over. Or is it enough to keep the probe interval low?
	annotations[annotation.ServiceHealthThresholdUnhealthy] = "2"
	annotations[annotation.ServiceHealthQuarantineTimeout] = "30s"

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   model.namespace,
			Name:        model.getOwningResourceName(),
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: "TCP",
					Port:     model.port,
				},
			},
		},
	}
}

func (r *lbFrontendReconciler) desiredEndpoints(model *lbFrontend, t2NodeIPs []string) (*corev1.Endpoints, error) {
	epAddresses := []corev1.EndpointAddress{}
	for _, addr := range t2NodeIPs {
		epAddresses = append(epAddresses, corev1.EndpointAddress{IP: addr})
	}

	return &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: model.namespace,
			Name:      model.getOwningResourceName(),
		},
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: epAddresses,
				Ports: []corev1.EndpointPort{
					{
						Name:     "http",
						Protocol: "TCP",
						Port:     model.port,
					},
				},
			},
		},
	}, nil
}

func (r *lbFrontendReconciler) getT2NodeAddresses(ctx context.Context) ([]string, error) {
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
