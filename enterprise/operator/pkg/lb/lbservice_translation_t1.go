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
	discoveryv1 "k8s.io/api/discovery/v1"
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
		ossannotation.ServiceNodeSelectorExposure: fmt.Sprintf("service.cilium.io/node in ( %s , %s )", lbNodeTypeT1, lbNodeTypeT1AndT2),
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

	if !model.isTCPProxyT1OnlyMode() && !model.isUDPProxyT1OnlyMode() {
		// T1 -> T2 delegation: If T2 is on the same node, just push the packet up to
		// T2 instead of IPIP encapsulation
		annotations[ossannotation.ServiceProxyDelegation] = string(loadbalancer.SVCProxyDelegationDelegateIfLocal)
	}

	// T1-only connectionfiltering
	var lbSourceRanges []string = nil

	if model.isTCPProxyT1OnlyMode() || model.isUDPProxy() /* t1 & t1&t2 for UDP !! */ {
		lbSourceRanges = r.getServiceLoadBalancingT1SourceRanges(model)
		if len(lbSourceRanges) > 0 {
			annotations[ossannotation.ServiceSourceRangesPolicy] = r.getServiceLoadBalancingT1SourceRangesPolicy(model)
		}
	}

	annotations["loadbalancer.isovalent.com/type"] = "t1"

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
			SessionAffinity:               r.getServiceSessionAffinity(model),
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

func (r *lbServiceT1Translator) endpointSubsetsFromT2Nodes(model *lbService) ([]discoveryv1.Endpoint, []discoveryv1.EndpointPort) {
	prot := corev1.ProtocolTCP
	if model.isUDPProxy() {
		prot = corev1.ProtocolUDP
	}

	return []discoveryv1.Endpoint{
			{
				Addresses: model.t2NodeIPs,
			},
		},
		[]discoveryv1.EndpointPort{
			{
				Name:     ptr.To(strings.ToLower(string(prot))),
				Protocol: ptr.To(prot),
				Port:     ptr.To(int32(model.port)),
			},
		}
}

func (r *lbServiceT1Translator) tcpEndpointSubsetsFromBackends(model *lbService) ([]discoveryv1.Endpoint, []discoveryv1.EndpointPort) {
	epAddresses := []string{}
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
				epAddresses = append(epAddresses, b.address)
			}
		}
	}

	return []discoveryv1.Endpoint{
			{
				Addresses: epAddresses,
			},
		},
		[]discoveryv1.EndpointPort{
			{
				Name:     ptr.To(strings.ToLower(string(corev1.ProtocolTCP))),
				Protocol: ptr.To(corev1.ProtocolTCP),
				Port:     ptr.To(int32(port)),
			},
		}
}

func (r *lbServiceT1Translator) udpEndpointSubsetsFromBackends(model *lbService) ([]discoveryv1.Endpoint, []discoveryv1.EndpointPort) {
	epAddresses := []string{}
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
				epAddresses = append(epAddresses, b.address)
			}
		}
	}

	return []discoveryv1.Endpoint{
			{
				Addresses: epAddresses,
			},
		},
		[]discoveryv1.EndpointPort{
			{
				Name:     ptr.To(strings.ToLower(string(corev1.ProtocolUDP))),
				Protocol: ptr.To(corev1.ProtocolUDP),
				Port:     ptr.To(int32(port)),
			},
		}
}

func (r *lbServiceT1Translator) DesiredEndpointSlice(model *lbService) *discoveryv1.EndpointSlice {
	if model.vip.assignedIPv4 == nil {
		return nil
	}

	endpoints, ports := r.getEndpointSliceInfo(model)

	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: model.namespace,
			Name:      model.getOwningResourceName(),
			Labels: map[string]string{
				discoveryv1.LabelServiceName: model.getOwningResourceName(),
				discoveryv1.LabelManagedBy:   "ilb",
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   endpoints,
		Ports:       ports,
	}
}

func (r *lbServiceT1Translator) getEndpointSliceInfo(model *lbService) ([]discoveryv1.Endpoint, []discoveryv1.EndpointPort) {
	if model.isTCPProxyT1OnlyMode() {
		return r.tcpEndpointSubsetsFromBackends(model)
	} else if model.isUDPProxyT1OnlyMode() {
		return r.udpEndpointSubsetsFromBackends(model)
	} else {
		return r.endpointSubsetsFromT2Nodes(model)
	}
}

func (r *lbServiceT1Translator) getServiceForwardingMode(model *lbService) string {
	if model.isTCPProxyT1OnlyMode() || model.isUDPProxyT1OnlyMode() {
		return string(loadbalancer.SVCForwardingModeSNAT)
	}

	return string(loadbalancer.SVCForwardingModeDSR)
}

func (r *lbServiceT1Translator) getServiceLoadBalancingAlgorithm(model *lbService) string {
	if model.isTCPProxyT1OnlyMode() && !model.usesTCPProxyPersistentBackendsWithSourceIP() {
		return "random"
	}

	// Note: UDPProxy with deployment mode T1-only uses maglev to provide UDP "session" support.

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

func (r *lbServiceT1Translator) getServiceSessionAffinity(model *lbService) corev1.ServiceAffinity {
	if !model.isTCPProxyT1OnlyMode() && !model.isUDPProxyT1OnlyMode() {
		return corev1.ServiceAffinityNone
	}

	if model.usesTCPProxyPersistentBackendsWithSourceIP() || model.usesUDPProxyPersistentBackendsWithSourceIP() {
		return corev1.ServiceAffinityClientIP
	}

	return corev1.ServiceAffinityNone
}
