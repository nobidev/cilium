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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/pkg/annotation"
	ossannotation "github.com/cilium/cilium/pkg/annotation"
)

type lbServiceT1Translator struct {
	config reconcilerConfig
}

func (r *lbServiceT1Translator) DesiredService(model *lbService) *corev1.Service {
	if model.vip.assignedIPv4 == nil {
		return nil
	}

	annotations := map[string]string{
		ossannotation.ServiceNodeExposure: lbNodeTypeT1,
	}

	// Set the sharing key (LBVIP name)
	annotations[ossannotation.LBIPAMSharingKey] = model.vip.name

	// Expose only LoadBalancer service
	annotations[ossannotation.ServiceTypeExposure] = "LoadBalancer"

	// Set the assigned IP address of the LBVIP as LB IPAM annotation.
	// This way we treat the Service of the LBVIP as the main leader from an
	// LB IPAM perspective. This way, when switching the LBVIP, the IP gets changed
	// correctly
	annotations[ossannotation.LBIPAMIPsKey] = *model.vip.assignedIPv4

	// TODO: should the following config be part of the lbService model? (infra?)

	// BGP
	annotations[annotation.ServiceHealthBGPAdvertiseThreshold] = "1"

	// T1 -> T2 health checking
	annotations[annotation.ServiceHealthHTTPPath] = r.config.T1T2HealthCheck.T1ProbeHttpPath
	annotations[annotation.ServiceHealthHTTPMethod] = r.config.T1T2HealthCheck.T1ProbeHttpMethod
	annotations[annotation.ServiceHealthProbeInterval] = fmt.Sprintf("%ds", r.getHealthCheckIntervalSeconds(model))
	annotations[annotation.ServiceHealthProbeTimeout] = fmt.Sprintf("%ds", r.config.T1T2HealthCheck.T1ProbeTimeoutSeconds)
	annotations[annotation.ServiceHealthThresholdHealthy] = "1"
	annotations[annotation.ServiceHealthThresholdUnhealthy] = "1"
	annotations[annotation.ServiceHealthQuarantineTimeout] = "0s" // disable quarantine timeout (defaults to 30s)

	// T1 -> T2 forwarding method
	annotations[ossannotation.ServiceForwardingMode] = "dsr"

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   model.namespace,
			Name:        model.getOwningResourceName(),
			Labels:      map[string]string{},
			Annotations: annotations,
		},
		Spec: corev1.ServiceSpec{
			Type:                          corev1.ServiceTypeLoadBalancer,
			AllocateLoadBalancerNodePorts: ptr.To(false),
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

func (r *lbServiceT1Translator) getHealthCheckIntervalSeconds(model *lbService) int {
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

	for _, r := range model.applications.getTLSProxyRoutes() {
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

func (r *lbServiceT1Translator) DesiredEndpoints(model *lbService) (*corev1.Endpoints, error) {
	if model.vip.assignedIPv4 == nil {
		return nil, nil
	}

	epAddresses := []corev1.EndpointAddress{}
	for _, addr := range model.t2NodeIPs {
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
