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

	// T1 -> {T2 | Backend} health checking
	if !model.isTCPProxyT1OnlyMode() {
		// The presence of these annotations will enable HTTP-based
		// health checking from T1 to T2 nodes
		annotations[annotation.ServiceHealthHTTPPath] = r.config.T1T2HealthCheck.T1ProbeHttpPath
		annotations[annotation.ServiceHealthHTTPMethod] = r.config.T1T2HealthCheck.T1ProbeHttpMethod
	} else {
		// For T1-only frontends, L4 healthchecks will be enabled
		// (connect for TCP, ICMP/Payload-based for UDP)
	}

	annotations[annotation.ServiceHealthProbeInterval] = fmt.Sprintf("%ds", r.getHealthCheckIntervalSeconds(model))
	annotations[annotation.ServiceHealthProbeTimeout] = fmt.Sprintf("%ds", r.config.T1T2HealthCheck.T1ProbeTimeoutSeconds)
	annotations[annotation.ServiceHealthThresholdHealthy] = "1"
	annotations[annotation.ServiceHealthThresholdUnhealthy] = "1"
	annotations[annotation.ServiceHealthQuarantineTimeout] = "0s" // disable quarantine timeout (defaults to 30s)

	// T1 -> {T2 | Backend} forwarding mode
	annotations[ossannotation.ServiceForwardingMode] = r.getServiceForwardingMode(model)

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: model.namespace,
			Name:      model.getOwningResourceName(),
			Labels: map[string]string{
				"loadbalancer.isovalent.com/vip-name": model.vip.name,
			},
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

	for _, b := range model.referencedBackends {
		if shortestInterval == 0 || b.healthCheckConfig.intervalSeconds < shortestInterval {
			shortestInterval = b.healthCheckConfig.intervalSeconds
		}
	}

	hcInterval := shortestInterval
	if shortestInterval > 1 {
		// Use half of shortest interval as health check interval
		hcInterval = shortestInterval / 2
	}

	return hcInterval
}

func (r *lbServiceT1Translator) endpointAddressesFromT2Nodes(model *lbService) []corev1.EndpointAddress {
	epAddresses := []corev1.EndpointAddress{}
	for _, addr := range model.t2NodeIPs {
		epAddresses = append(epAddresses, corev1.EndpointAddress{IP: addr})
	}
	return epAddresses
}

func (r *lbServiceT1Translator) endpointAddressesFromBackends(model *lbService) []corev1.EndpointAddress {
	epAddresses := []corev1.EndpointAddress{}

	routes := model.applications.tcpProxy.routes
	if len(routes) == 1 {
		backend, ok := model.referencedBackends[model.applications.tcpProxy.routes[0].backendRef.name]
		if ok {
			for _, b := range backend.lbBackends {
				epAddresses = append(epAddresses, corev1.EndpointAddress{IP: b.address})
			}
		}
	}

	return epAddresses
}

func (r *lbServiceT1Translator) DesiredEndpoints(model *lbService) (*corev1.Endpoints, error) {
	if model.vip.assignedIPv4 == nil {
		return nil, nil
	}

	var epAddresses []corev1.EndpointAddress
	if model.applications.tcpProxy == nil || model.applications.tcpProxy.tierMode == tierModeT2 {
		epAddresses = r.endpointAddressesFromT2Nodes(model)
	} else {
		epAddresses = r.endpointAddressesFromBackends(model)
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

func (r *lbServiceT1Translator) getServiceForwardingMode(model *lbService) string {
	if model.isTCPProxyT1OnlyMode() {
		return "snat"
	}

	return "dsr"
}
