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
	"log/slog"
	"maps"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/pkg/annotation"
	ossannotation "github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type lbServiceT1Translator struct {
	logger *slog.Logger
	config reconcilerConfig
}

func (r *lbServiceT1Translator) toServicePort(model *lbService) *corev1.ServicePort {
	if model.isUDPProxy() {
		return &corev1.ServicePort{
			Name:     strings.ToLower(string(corev1.ProtocolUDP)),
			Protocol: corev1.ProtocolUDP,
			Port:     model.port,
		}
	}

	return &corev1.ServicePort{
		Name:     strings.ToLower(string(corev1.ProtocolTCP)),
		Protocol: corev1.ProtocolTCP,
		Port:     model.port,
	}
}

func (r *lbServiceT1Translator) DesiredService(model *lbService) *corev1.Service {
	if model.vip.assignedIPv4 == nil {
		return nil
	}

	annotations := map[string]string{
		ossannotation.ServiceNodeExposure: lbNodeTypeT1,
	}

	// Set the assigned IP address of the LBVIP as LB IPAM annotation.
	// This way we treat the Service of the LBVIP as the main leader from an
	// LB IPAM perspective. This way, when switching the LBVIP, the IP gets changed
	// correctly
	annotations[ossannotation.LBIPAMIPsKey] = *model.vip.assignedIPv4

	// Set the sharing key (LBVIP name)
	annotations[ossannotation.LBIPAMSharingKey] = model.vip.name

	// BGP
	annotations[annotation.ServiceHealthBGPAdvertiseThreshold] = "1"

	// Expose only LoadBalancer service
	annotations[ossannotation.ServiceTypeExposure] = string(corev1.ServiceTypeLoadBalancer)

	// T1 -> {T2 | Backend} forwarding mode
	annotations[ossannotation.ServiceForwardingMode] = r.getServiceForwardingMode(model)

	// T1 -> T2 loadbalancing algorithm
	annotations[ossannotation.ServiceLoadBalancingAlgorithm] = r.getServiceLoadBalancingAlgorithm(model)

	// T1 -> {T2 | Backend} health checking
	maps.Copy(annotations, r.getHealthCheckAnnotations(model))

	// T1-only connectionfiltering
	var lbSourceRanges []string = nil

	if model.isTCPProxyT1OnlyMode() || model.isUDPProxy() /* t1 & t1&t2 for UDP !! */ {
		lbSourceRanges = r.getServiceLoadBalancingT1SourceRanges(model)
		if len(lbSourceRanges) > 0 {
			annotations[ossannotation.ServiceSourceRangesPolicy] = r.getServiceLoadBalancingT1SourceRangesPolicy(model)
		}
	}

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
			Ports:                         []corev1.ServicePort{*r.toServicePort(model)},
			LoadBalancerSourceRanges:      lbSourceRanges,
		},
	}
}

func (r *lbServiceT1Translator) getHealthCheckAnnotations(model *lbService) map[string]string {
	annotations := map[string]string{}

	if !model.isTCPProxyT1OnlyMode() && !model.isUDPProxyT1OnlyMode() {
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

	return annotations
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

func (r *lbServiceT1Translator) endpointSubsetsFromT2Nodes(model *lbService) []corev1.EndpointSubset {
	epAddresses := []corev1.EndpointAddress{}
	for _, addr := range model.t2NodeIPs {
		epAddresses = append(epAddresses, corev1.EndpointAddress{IP: addr})
	}

	prot := corev1.ProtocolTCP
	if model.isUDPProxy() {
		prot = corev1.ProtocolUDP
	}

	return []corev1.EndpointSubset{
		{
			Addresses: epAddresses,
			Ports: []corev1.EndpointPort{
				{
					Name:     strings.ToLower(string(prot)),
					Protocol: prot,
					Port:     model.port,
				},
			},
		},
	}
}

func (r *lbServiceT1Translator) tcpEndpointSubsetsFromBackends(model *lbService) []corev1.EndpointSubset {
	epAddresses := []corev1.EndpointAddress{}
	port := uint32(0)

	for _, tr := range model.applications.tcpProxy.routes {
		backend, ok := model.referencedBackends[tr.backendRef.name]
		if ok {
			for _, b := range backend.lbBackends {
				if port == 0 {
					port = b.port
				}
				if port != b.port {
					r.logger.Debug("Skipping incompatible backend",
						logfields.Resource, types.NamespacedName{Namespace: model.namespace, Name: model.name},
						logfields.Address, b.address,
						logfields.Port, b.port,
						logfields.Reason, "T1-only service does not support backends with different ports")
					continue
				}
				epAddresses = append(epAddresses, corev1.EndpointAddress{IP: b.address})
			}
		}
	}

	return []corev1.EndpointSubset{
		{
			Addresses: epAddresses,
			Ports: []corev1.EndpointPort{
				{
					Name:     strings.ToLower(string(corev1.ProtocolTCP)),
					Protocol: corev1.ProtocolTCP,
					Port:     int32(port),
				},
			},
		},
	}
}

func (r *lbServiceT1Translator) udpEndpointSubsetsFromBackends(model *lbService) []corev1.EndpointSubset {
	epAddresses := []corev1.EndpointAddress{}
	port := uint32(0)

	for _, tr := range model.applications.udpProxy.routes {
		backend, ok := model.referencedBackends[tr.backendRef.name]
		if ok {
			for _, b := range backend.lbBackends {
				if port == 0 {
					port = b.port
				}
				if port != b.port {
					r.logger.Debug("Skipping incompatible backend",
						logfields.Resource, types.NamespacedName{Namespace: model.namespace, Name: model.name},
						logfields.Address, b.address,
						logfields.Port, b.port,
						logfields.Reason, "T1-only service does not support backends with different ports")
					continue
				}
				epAddresses = append(epAddresses, corev1.EndpointAddress{IP: b.address})
			}
		}
	}

	return []corev1.EndpointSubset{
		{
			Addresses: epAddresses,
			Ports: []corev1.EndpointPort{
				{
					Name:     strings.ToLower(string(corev1.ProtocolUDP)),
					Protocol: corev1.ProtocolUDP,
					Port:     int32(port),
				},
			},
		},
	}
}

func (r *lbServiceT1Translator) DesiredEndpoints(model *lbService) *corev1.Endpoints {
	if model.vip.assignedIPv4 == nil {
		return nil
	}

	var epSubsets []corev1.EndpointSubset

	if model.isTCPProxyT1OnlyMode() {
		epSubsets = r.tcpEndpointSubsetsFromBackends(model)
	} else if model.isUDPProxyT1OnlyMode() {
		epSubsets = r.udpEndpointSubsetsFromBackends(model)
	} else {
		epSubsets = r.endpointSubsetsFromT2Nodes(model)
	}

	return &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: model.namespace,
			Name:      model.getOwningResourceName(),
		},
		Subsets: epSubsets,
	}
}

func (r *lbServiceT1Translator) getServiceForwardingMode(model *lbService) string {
	if model.isTCPProxyT1OnlyMode() || model.isUDPProxyT1OnlyMode() {
		return string(loadbalancer.SVCForwardingModeSNAT)
	}

	return string(loadbalancer.SVCForwardingModeDSR)
}

func (r *lbServiceT1Translator) getServiceLoadBalancingAlgorithm(model *lbService) string {
	if model.isTCPProxyT1OnlyMode() || model.isUDPProxyT1OnlyMode() {
		return "random"
	}

	return "maglev"
}

func (r *lbServiceT1Translator) getServiceLoadBalancingT1SourceRanges(model *lbService) []string {
	switch {
	case model.isTCPProxy():
		for _, tr := range model.applications.tcpProxy.routes {
			if tr.connectionFiltering != nil {
				lbSourceRanges := []string{}
				for _, cfr := range tr.connectionFiltering.rules {
					if cfr.sourceCIDR != nil {
						lbSourceRanges = append(lbSourceRanges, fmt.Sprintf("%s/%d", cfr.sourceCIDR.addressPrefix, cfr.sourceCIDR.prefixLen))
					}
				}

				// Only one TCPProxy route allowed for the time being
				return lbSourceRanges
			}
		}
	case model.isUDPProxy():
		for _, tr := range model.applications.udpProxy.routes {
			if tr.connectionFiltering != nil {
				lbSourceRanges := []string{}
				for _, cfr := range tr.connectionFiltering.rules {
					if cfr.sourceCIDR != nil {
						lbSourceRanges = append(lbSourceRanges, fmt.Sprintf("%s/%d", cfr.sourceCIDR.addressPrefix, cfr.sourceCIDR.prefixLen))
					}
				}

				// Only one UDPProxy route allowed for the time being
				return lbSourceRanges
			}
		}
	}

	return nil
}

func (r *lbServiceT1Translator) getServiceLoadBalancingT1SourceRangesPolicy(model *lbService) string {
	switch {
	case model.isTCPProxy():
		for _, tr := range model.applications.tcpProxy.routes {
			if tr.connectionFiltering != nil {
				policy := "allow"
				if tr.connectionFiltering.ruleType == ruleTypeDeny {
					policy = "deny"
				}

				// Only one TCPProxy route allowed for the time being
				return policy
			}
		}
	case model.isUDPProxy():
		for _, tr := range model.applications.udpProxy.routes {
			if tr.connectionFiltering != nil {
				policy := "allow"
				if tr.connectionFiltering.ruleType == ruleTypeDeny {
					policy = "deny"
				}

				// Only one UDPProxy route allowed for the time being
				return policy
			}
		}
	}

	return ""
}
