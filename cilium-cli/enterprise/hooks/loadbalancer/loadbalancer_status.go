// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"context"
	"fmt"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/api/v1/models"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func (s *LoadbalancerClient) GetLoadbalancerStatusModel(ctx context.Context) (*LoadbalancerStatusModel, error) {
	ctx, cancelFn := context.WithTimeout(ctx, s.params.WaitDuration)
	defer cancelFn()

	if err := s.initNodeAgentPods(ctx); err != nil {
		return nil, fmt.Errorf("failed to fetch Node Agent Pods: %w", err)
	}
	bgpRoutes, err := s.getBGPRoutes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch T1 BGP routes: %w", err)
	}

	bgpPeers, err := s.getBGPPeers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch T1 BGP peers: %w", err)
	}
	t1ServicesRoutes, err := s.getHealthcheckT1(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch T1 Services: %w", err)
	}

	t2EnvoyConfigs, err := s.getHealthcheckT2(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch T2 Envoyconfigs: %w", err)
	}

	vips, err := s.client.ListLBVIPs(ctx, "", metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	services, err := s.client.ListLBServices(ctx, "", metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	lsm := &LoadbalancerStatusModel{}

	// Summary
	lsm.Summary = LoadbalancerStatusModelSummary{
		NrOfT1Nodes:  len(s.t1AgentPods),
		NrOfT2Nodes:  len(s.t2AgentPods),
		NrOfServices: len(services.Items),
		NrOfVIPs:     len(vips.Items),
	}

	for _, f := range services.Items {
		serviceModel := LoadbalancerStatusModelService{
			Namespace:         f.Namespace,
			Name:              f.Name,
			VIP:               s.getVIP(f),
			Port:              uint(f.Spec.Port),
			Type:              s.getType(f),
			DeploymentMode:    s.getDeploymentMode(f),
			BGPPeerStatus:     s.getBGPPeerStatus(f, bgpRoutes, bgpPeers),
			BGPNodeStatus:     s.getBGPNodeStatus(f, bgpRoutes),
			T1NodeStatus:      s.getT1Status(f, t1ServicesRoutes),
			T1T2HCStatus:      s.getHCT1T2(f, t1ServicesRoutes),
			T2NodeStatus:      s.getT2Status(f, t2EnvoyConfigs),
			T2BackendHCStatus: s.getHCT2Backends(f, t2EnvoyConfigs),
			BackendpoolStatus: s.getBackends(f, t1ServicesRoutes, t2EnvoyConfigs),
			Status:            s.getOverallStatus(f, bgpRoutes),
		}

		if s.includedInFilter(serviceModel) {
			lsm.Services = append(lsm.Services, serviceModel)
		}

	}

	return lsm, nil
}

func (s *LoadbalancerClient) includedInFilter(serviceModel LoadbalancerStatusModelService) bool {
	if s.params.ServiceNamespace != "" && serviceModel.Namespace != s.params.ServiceNamespace {
		return false
	}

	if s.params.ServiceName != "" && serviceModel.Name != s.params.ServiceName {
		return false
	}

	if s.params.ServiceVIP != "" && serviceModel.VIP != s.params.ServiceVIP {
		return false
	}

	if s.params.ServicePort != 0 && serviceModel.Port != s.params.ServicePort {
		return false
	}

	if s.params.ServiceStatus != "" && serviceModel.Status != s.params.ServiceStatus {
		return false
	}

	return true
}

func (s *LoadbalancerClient) getType(service isovalentv1alpha1.LBService) string {
	switch {
	case service.Spec.Applications.HTTPProxy != nil:
		return "HTTP Proxy"
	case service.Spec.Applications.HTTPSProxy != nil:
		return "HTTPS Proxy"
	case service.Spec.Applications.TLSPassthrough != nil:
		return "TLS Passthrough"
	case service.Spec.Applications.TLSProxy != nil:
		return "TLS Proxy"
	case service.Spec.Applications.TCPProxy != nil:
		return "TCP Proxy"
	case service.Spec.Applications.UDPProxy != nil:
		return "UDP Proxy"
	}

	return "N/A"
}

func (s *LoadbalancerClient) getDeploymentMode(service isovalentv1alpha1.LBService) string {
	switch {
	case service.Spec.Applications.TCPProxy != nil:
		if service.Status.Applications.TCPProxy == nil {
			return "N/A"
		}

		if service.Status.Applications.TCPProxy.DeploymentMode != nil &&
			*service.Status.Applications.TCPProxy.DeploymentMode == isovalentv1alpha1.LBTCPProxyDeploymentModeTypeT1Only {
			return "T1"
		}
	}

	return "T1-T2"
}

func (s *LoadbalancerClient) getVIP(lbsvc isovalentv1alpha1.LBService) string {
	if lbsvc.Status.Addresses.IPv4 != nil {
		return *lbsvc.Status.Addresses.IPv4
	}

	return "N/A"
}

func (s *LoadbalancerClient) getBGPPeerStatus(lbsvc isovalentv1alpha1.LBService, nodeBGPRoutes map[string][]*models.BgpRoute, nodeBGPPeers map[string][]*models.BgpPeer) LoadbalancerStatusModelSimpleStatus {
	if lbsvc.Status.Addresses.IPv4 == nil {
		return LoadbalancerStatusModelSimpleStatus{
			Status: "N/A",
			OK:     0,
			Total:  0,
		}
	}

	nrPeers := 0
	activePeers := map[string]struct{}{}

	for _, p := range nodeBGPPeers {
		for _, pp := range p {
			nrPeers++
			if pp.SessionState == "established" {
				activePeers[fmt.Sprintf("%s-%d", pp.PeerAddress, pp.PeerAsn)] = struct{}{}
			}
		}
	}

	nrOk := 0

	for _, r := range nodeBGPRoutes {
		for _, br := range r {
			if br.Prefix == *lbsvc.Status.Addresses.IPv4+"/32" {
				if _, ok := activePeers[fmt.Sprintf("%s-%d", br.Neighbor, br.RouterAsn)]; ok {
					nrOk++
				}
			}
		}
	}

	return LoadbalancerStatusModelSimpleStatus{
		Status: s.statusText(nrOk, nrPeers),
		OK:     nrOk,
		Total:  nrPeers,
	}
}

func (s *LoadbalancerClient) getBGPNodeStatus(lbsvc isovalentv1alpha1.LBService, nodeBGPRoutes map[string][]*models.BgpRoute) LoadbalancerStatusModelSimpleStatus {
	if lbsvc.Status.Addresses.IPv4 == nil {
		return LoadbalancerStatusModelSimpleStatus{
			Status: "N/A",
			OK:     0,
			Total:  0,
		}
	}

	nrOk := 0

	for _, r := range nodeBGPRoutes {
		for _, br := range r {
			if br.Prefix == *lbsvc.Status.Addresses.IPv4+"/32" {
				nrOk++
				// break and don't take other announcements to other peers into account
				break
			}
		}
	}

	return LoadbalancerStatusModelSimpleStatus{
		Status: s.statusText(nrOk, len(nodeBGPRoutes)),
		OK:     nrOk,
		Total:  len(nodeBGPRoutes),
	}
}

func (s *LoadbalancerClient) getT1Status(lbsvc isovalentv1alpha1.LBService, nodeServices map[string][]*models.Service) LoadbalancerStatusModelSimpleStatus {
	if lbsvc.Status.Addresses.IPv4 == nil {
		return LoadbalancerStatusModelSimpleStatus{
			Status: "N/A",
			OK:     0,
			Total:  0,
		}
	}

	usedNodes := map[string]struct{}{}

	for nodeName, sn := range nodeServices {
		for _, s := range sn {
			if s.Status != nil && s.Status.Realized != nil && s.Status.Realized.FrontendAddress != nil && s.Status.Realized.Flags != nil &&
				s.Status.Realized.Flags.Type == "LoadBalancer" &&
				s.Status.Realized.Flags.Name == "lbfe-"+lbsvc.Name &&
				s.Status.Realized.FrontendAddress.IP == *lbsvc.Status.Addresses.IPv4 &&
				s.Status.Realized.FrontendAddress.Port == uint16(lbsvc.Spec.Port) {

				for _, b := range s.Status.Realized.BackendAddresses {
					if b.State == "active" {
						usedNodes[nodeName] = struct{}{}
						break
					}
				}
			}
		}
	}

	return LoadbalancerStatusModelSimpleStatus{
		Status: s.statusText(len(usedNodes), len(nodeServices)),
		OK:     len(usedNodes),
		Total:  len(nodeServices),
	}
}

func (s *LoadbalancerClient) getHCT1T2(lbsvc isovalentv1alpha1.LBService, nodeServices map[string][]*models.Service) LoadbalancerStatusModelSimpleStatus {
	if lbsvc.Status.Addresses.IPv4 == nil {
		return LoadbalancerStatusModelSimpleStatus{
			Status: "N/A",
			OK:     0,
			Total:  0,
		}
	}

	nrOk := 0
	nrTotal := 0

	for _, sn := range nodeServices {
		for _, s := range sn {
			if s.Status != nil && s.Status.Realized != nil && s.Status.Realized.FrontendAddress != nil && s.Status.Realized.Flags != nil &&
				s.Status.Realized.Flags.Type == "LoadBalancer" &&
				s.Status.Realized.Flags.Name == "lbfe-"+lbsvc.Name &&
				s.Status.Realized.FrontendAddress.IP == *lbsvc.Status.Addresses.IPv4 &&
				s.Status.Realized.FrontendAddress.Port == uint16(lbsvc.Spec.Port) {

				for _, b := range s.Status.Realized.BackendAddresses {
					nrTotal++
					if b.State == "active" {
						nrOk++
					}
				}
			}
		}
	}

	return LoadbalancerStatusModelSimpleStatus{
		Status: s.statusText(nrOk, nrTotal),
		OK:     nrOk,
		Total:  nrTotal,
	}
}

func (s *LoadbalancerClient) isT1Only(lbsvc isovalentv1alpha1.LBService) bool {
	if lbsvc.Spec.Applications.TCPProxy != nil && (lbsvc.Spec.Applications.TCPProxy.ForceDeploymentMode == nil || slices.Contains([]isovalentv1alpha1.LBTCPProxyForceDeploymentModeType{isovalentv1alpha1.LBTCPProxyForceDeploymentModeAuto, isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1}, *lbsvc.Spec.Applications.TCPProxy.ForceDeploymentMode)) {
		return true
	}

	if lbsvc.Spec.Applications.UDPProxy != nil && (lbsvc.Spec.Applications.UDPProxy.ForceDeploymentMode == nil || slices.Contains([]isovalentv1alpha1.LBUDPProxyForceDeploymentModeType{isovalentv1alpha1.LBUDPProxyForceDeploymentModeAuto, isovalentv1alpha1.LBUDPProxyForceDeploymentModeT1}, *lbsvc.Spec.Applications.UDPProxy.ForceDeploymentMode)) {
		return true
	}

	return false
}

func (s *LoadbalancerClient) getT2Status(lbsvc isovalentv1alpha1.LBService, nodeEnvoyConfigs map[string]*EnvoyConfigModel) LoadbalancerStatusModelSimpleStatus {
	if s.isT1Only(lbsvc) {
		return LoadbalancerStatusModelSimpleStatus{
			Status: "",
			OK:     0,
			Total:  0,
		}
	}

	if lbsvc.Status.Addresses.IPv4 == nil {
		return LoadbalancerStatusModelSimpleStatus{
			Status: "N/A",
			OK:     0,
			Total:  0,
		}
	}

	usedNodes := map[string]struct{}{}

	for nodeName, ecn := range nodeEnvoyConfigs {
		for _, c := range ecn.Configs {
			switch c.Type {
			case "type.googleapis.com/envoy.admin.v3.ListenersConfigDump":
				// default/lbfe-lb-1/frontend_listener
				listenerFound := false

				for _, l := range c.DynamicListeners {
					if l.Name == fmt.Sprintf("%s/lbfe-%s/frontend_listener", lbsvc.Namespace, lbsvc.Name) &&
						l.ActiveState.Listener.Address.SocketAddress.Address == *lbsvc.Status.Addresses.IPv4 &&
						l.ActiveState.Listener.Address.SocketAddress.PortValue == int(lbsvc.Spec.Port) {
						listenerFound = true
						break
					}
				}
				if !listenerFound {
					continue
				}

			case "type.googleapis.com/envoy.admin.v3.RoutesConfigDump":
				// default/lbfe-lb-1/frontend_routeconfig_https
				routeFound := false
				for _, r := range c.DynamicRouteConfigs {
					if strings.HasPrefix(r.RouteConfig.Name, fmt.Sprintf("%s/lbfe-%s/", lbsvc.Namespace, lbsvc.Name)) {
						routeFound = true
						break
					}
				}
				if !routeFound {
					continue
				}

			case "type.googleapis.com/envoy.admin.v3.ClustersConfigDump":
				// default/lbfe-lb-8/backend_cluster_https_0
				clusterFound := false
				for _, c := range c.DynamicActiveClusters {
					if strings.HasPrefix(c.Cluster.Name, fmt.Sprintf("%s/lbfe-%s/", lbsvc.Namespace, lbsvc.Name)) {
						clusterFound = true
						break
					}
				}
				if !clusterFound {
					continue
				}

			case "type.googleapis.com/envoy.admin.v3.EndpointsConfigDump":
				// default/lbfe-lb-1/backend_cluster_https_0
				for _, e := range c.DynamicEndpointConfigs {
					if strings.HasPrefix(e.EndpointConfig.ClusterName, fmt.Sprintf("%s/lbfe-%s/", lbsvc.Namespace, lbsvc.Name)) {
						for _, ep := range e.EndpointConfig.Endpoints {
							for _, epc := range ep.LbEndpoints {
								if epc.HealthStatus == "HEALTHY" {
									usedNodes[nodeName] = struct{}{}
								}
							}
						}
					}
				}
			}
		}
	}

	return LoadbalancerStatusModelSimpleStatus{
		Status: s.statusText(len(usedNodes), len(nodeEnvoyConfigs)),
		OK:     len(usedNodes),
		Total:  len(nodeEnvoyConfigs),
	}
}

func (s *LoadbalancerClient) getHCT2Backends(lbsvc isovalentv1alpha1.LBService, nodeEnvoyConfigs map[string]*EnvoyConfigModel) LoadbalancerStatusModelSimpleStatus {
	if s.isT1Only(lbsvc) {
		return LoadbalancerStatusModelSimpleStatus{
			Status: "",
			OK:     0,
			Total:  0,
		}
	}

	if lbsvc.Status.Addresses.IPv4 == nil {
		return LoadbalancerStatusModelSimpleStatus{
			Status: "N/A",
			OK:     0,
			Total:  0,
		}
	}

	nrOk := 0
	nrTotal := 0

	for _, ecn := range nodeEnvoyConfigs {
		for _, c := range ecn.Configs {
			if c.Type == "type.googleapis.com/envoy.admin.v3.EndpointsConfigDump" {
				// default/lbfe-lb-1/backend_cluster_https_0
				for _, e := range c.DynamicEndpointConfigs {
					if strings.HasPrefix(e.EndpointConfig.ClusterName, fmt.Sprintf("%s/lbfe-%s/", lbsvc.Namespace, lbsvc.Name)) {
						for _, ep := range e.EndpointConfig.Endpoints {
							for _, epc := range ep.LbEndpoints {
								nrTotal++
								if epc.HealthStatus == "HEALTHY" {
									nrOk++
								}
							}
						}
					}
				}
			}
		}
	}

	return LoadbalancerStatusModelSimpleStatus{
		Status: s.statusText(nrOk, nrTotal),
		OK:     nrOk,
		Total:  nrTotal,
	}
}

func (s *LoadbalancerClient) getBackends(lbsvc isovalentv1alpha1.LBService, nodeT1Services map[string][]*models.Service, nodeEnvoyConfigs map[string]*EnvoyConfigModel) LoadbalancerStatusModelGroupedStatus {
	if lbsvc.Status.Addresses.IPv4 == nil {
		return LoadbalancerStatusModelGroupedStatus{
			Status: "N/A",
		}
	}

	var status map[string]map[string]int
	nrOfNodes := 0

	if s.isT1Only(lbsvc) {
		status = s.getBackendStatusFromT1(lbsvc, nodeT1Services)
		nrOfNodes = len(nodeT1Services)
	} else {
		status = s.getBackendStatusFromT2(lbsvc, nodeEnvoyConfigs)
		nrOfNodes = len(nodeEnvoyConfigs)
	}

	total := 0
	totalOk := 0

	groups := []LoadbalancerStatusModelSimpleStatus{}

	for _, endpoints := range status {
		nrOk := 0
		for _, v := range endpoints {
			total++
			if v == nrOfNodes {
				nrOk++
				totalOk++
			}
		}

		groups = append(groups, LoadbalancerStatusModelSimpleStatus{
			Status: s.statusText(nrOk, len(endpoints)),
			OK:     nrOk,
			Total:  len(endpoints),
		})
	}

	return LoadbalancerStatusModelGroupedStatus{
		Status: s.statusText(totalOk, total),
		Groups: groups,
	}
}

func (s *LoadbalancerClient) getBackendStatusFromT1(lbsvc isovalentv1alpha1.LBService, nodeT1Services map[string][]*models.Service) map[string]map[string]int {
	status := map[string]map[string]int{}

	for _, sn := range nodeT1Services {
		for _, s := range sn {
			if s.Status != nil && s.Status.Realized != nil && s.Status.Realized.FrontendAddress != nil && s.Status.Realized.Flags != nil &&
				s.Status.Realized.Flags.Type == "LoadBalancer" &&
				s.Status.Realized.Flags.Name == "lbfe-"+lbsvc.Name &&
				s.Status.Realized.FrontendAddress.IP == *lbsvc.Status.Addresses.IPv4 &&
				s.Status.Realized.FrontendAddress.Port == uint16(lbsvc.Spec.Port) {

				for _, b := range s.Status.Realized.BackendAddresses {
					if _, ok := status[s.Spec.Flags.Namespace+"-"+s.Spec.Flags.Name]; !ok {
						status[s.Spec.Flags.Namespace+"-"+s.Spec.Flags.Name] = map[string]int{}
					}

					key := fmt.Sprintf("%s-%d", *b.IP, b.Port)
					if _, ok := status[s.Spec.Flags.Namespace+"-"+s.Spec.Flags.Name][key]; !ok {
						status[s.Spec.Flags.Namespace+"-"+s.Spec.Flags.Name][key] = 0
					}

					if b.State == "active" {
						status[s.Spec.Flags.Namespace+"-"+s.Spec.Flags.Name][key] = status[s.Spec.Flags.Namespace+"-"+s.Spec.Flags.Name][key] + 1
					}
				}
			}
		}
	}

	return status
}

func (s *LoadbalancerClient) getBackendStatusFromT2(lbsvc isovalentv1alpha1.LBService, nodeEnvoyConfigs map[string]*EnvoyConfigModel) map[string]map[string]int {
	status := map[string]map[string]int{}

	for _, ecn := range nodeEnvoyConfigs {
		for _, c := range ecn.Configs {
			switch c.Type {
			case "type.googleapis.com/envoy.admin.v3.EndpointsConfigDump":
				// default/lbfe-lb-1/backend_cluster_https_0
				for _, e := range c.DynamicEndpointConfigs {
					if strings.HasPrefix(e.EndpointConfig.ClusterName, fmt.Sprintf("%s/lbfe-%s/", lbsvc.Namespace, lbsvc.Name)) {
						for _, ep := range e.EndpointConfig.Endpoints {
							for _, epc := range ep.LbEndpoints {
								if _, ok := status[e.EndpointConfig.ClusterName]; !ok {
									status[e.EndpointConfig.ClusterName] = map[string]int{}
								}

								key := fmt.Sprintf("%s-%d", epc.Endpoint.Address.SocketAddress.Address, epc.Endpoint.Address.SocketAddress.PortValue)
								if _, ok := status[e.EndpointConfig.ClusterName][key]; !ok {
									status[e.EndpointConfig.ClusterName][key] = 0
								}

								if epc.HealthStatus == "HEALTHY" {
									status[e.EndpointConfig.ClusterName][key] = status[e.EndpointConfig.ClusterName][key] + 1
								}
							}
						}
					}
				}
			}
		}
	}

	return status
}

func (s *LoadbalancerClient) getOverallStatus(lbsvc isovalentv1alpha1.LBService, nodeBGPRoutes map[string][]*models.BgpRoute) string {
	if lbsvc.Status.Addresses.IPv4 == nil {
		return "OFFLINE"
	}

	nrOk := 0

	for _, r := range nodeBGPRoutes {
		for _, br := range r {
			if br.Prefix == *lbsvc.Status.Addresses.IPv4+"/32" {
				nrOk++
			}
		}
	}

	if nrOk == 0 {
		return "OFFLINE"
	}

	return "ONLINE"
}

func (s *LoadbalancerClient) statusText(ok, total int) string {
	if ok == total {
		return "OK"
	}

	return "DEG"
}
