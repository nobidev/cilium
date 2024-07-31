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
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/enterprise/pkg/annotation"
	ossannotation "github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/addressing"
)

func (r *lbFrontendReconciler) desiredService(model *lbFrontend) *corev1.Service {
	labels := map[string]string{
		"service.cilium.io/node": "t1",
	}

	annotations := map[string]string{}

	// Set the sharing key (LBVIP name)
	annotations[ossannotation.LBIPAMSharingKey] = model.vip.name
	if model.vip.requestedIPv4 != nil {
		// If there's requested IP address, we need to set ips annotation
		annotations[ossannotation.LBIPAMIPsKey] = *model.vip.requestedIPv4
	}

	// TODO: should the following config be part of the lbFrontend model? (infra?)

	// BGP
	annotations[annotation.ServiceHealthBGPAdvertiseThreshold] = "1"

	// T1 -> T2 health checking
	annotations[annotation.ServiceHealthHTTPPath] = healthCheckHttpPath
	annotations[annotation.ServiceHealthHTTPMethod] = healthCheckHttpMethod
	annotations[annotation.ServiceHealthProbeInterval] = fmt.Sprintf("%ds", getHealthCheckIntervalSeconds(model))
	annotations[annotation.ServiceHealthProbeTimeout] = fmt.Sprintf("%ds", r.config.T1HealthCheck.ProbeTimeoutSeconds)
	annotations[annotation.ServiceHealthThresholdHealthy] = "1"
	annotations[annotation.ServiceHealthThresholdUnhealthy] = "1"
	annotations[annotation.ServiceHealthQuarantineTimeout] = "0s" // disable quarantine timeout (defaults to 30s)

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

func getHealthCheckIntervalSeconds(model *lbFrontend) int {
	shortestInterval := 0

	for _, r := range model.applications.getHTTPProxyRoutes() {
		if shortestInterval == 0 || r.backend.healthCheckConfig.intervalSeconds < shortestInterval {
			shortestInterval = r.backend.healthCheckConfig.intervalSeconds
		}
	}

	for _, r := range model.applications.getHTTPSProxyRoutes() {
		if shortestInterval == 0 || r.backend.healthCheckConfig.intervalSeconds < shortestInterval {
			shortestInterval = r.backend.healthCheckConfig.intervalSeconds
		}
	}

	for _, r := range model.applications.getTLSPassthroughRoutes() {
		if shortestInterval == 0 || r.backend.healthCheckConfig.intervalSeconds < shortestInterval {
			shortestInterval = r.backend.healthCheckConfig.intervalSeconds
		}
	}

	hcInterval := shortestInterval
	if shortestInterval > 1 {
		// Use half of shortest interval as health check interval
		hcInterval = shortestInterval / 2
	}

	return hcInterval
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

func (r *lbFrontendReconciler) ensureEndpointsDeleted(ctx context.Context, model *lbFrontend) error {
	ep := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: model.namespace,
			Name:      model.getOwningResourceName(),
		},
	}
	if err := r.client.Delete(ctx, ep); err != nil {
		if !k8serrors.IsNotFound(err) {
			return err
		}
		// Endpoints does not exist, which is fine
	}
	return nil
}

func (r *lbFrontendReconciler) getT2NodeAddresses(ctx context.Context) ([]string, error) {
	nodeStore, err := r.nodeSource.Store(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get node store: %w", err)
	}

	t2NodeIPs := []string{}

	allNodes := nodeStore.List()
	for _, cn := range allNodes {
		if v := cn.Labels["service.cilium.io/node"]; v == "t2" {
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

func (r *lbFrontendReconciler) ensureServiceDeleted(ctx context.Context, model *lbFrontend) error {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: model.namespace,
			Name:      model.getOwningResourceName(),
		},
	}
	if err := r.client.Delete(ctx, svc); err != nil {
		if !k8serrors.IsNotFound(err) {
			return err
		}
		// Service does not exist, which is fine
	}
	return nil
}
