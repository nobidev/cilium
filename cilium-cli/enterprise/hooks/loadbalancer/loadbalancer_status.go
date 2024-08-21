// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"context"
	"fmt"
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

	frontends, err := s.client.ListLBFrontends(ctx, "", metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	lsm := &LoadbalancerStatusModel{}

	// Summary
	lsm.Summary = LoadbalancerStatusModelSummary{
		NrOfT1Nodes:   len(s.t1AgentPods),
		NrOfT2Nodes:   len(s.t2AgentPods),
		NrOfFrontends: len(frontends.Items),
		NrOfVIPs:      len(vips.Items),
	}

	for _, f := range frontends.Items {
		frontendModel := LoadbalancerStatusModelFrontend{
			Namespace:         f.Namespace,
			Name:              f.Name,
			VIP:               s.getVIP(f),
			Port:              uint(f.Spec.Port),
			Type:              s.getType(f),
			BGPPeerStatus:     s.getBGPPeerStatus(f, bgpRoutes, bgpPeers),
			BGPNodeStatus:     s.getBGPNodeStatus(f, bgpRoutes),
			T1NodeStatus:      s.getT1Status(f, t1ServicesRoutes),
			T1T2HCStatus:      s.getHCT1T2(f, t1ServicesRoutes),
			T2NodeStatus:      s.getT2Status(f, t2EnvoyConfigs),
			T2BackendHCStatus: s.getHCT2Backends(f, t2EnvoyConfigs),
			BackendpoolStatus: s.getBackends(f, t2EnvoyConfigs),
			Status:            s.getOverallStatus(f, bgpRoutes),
		}

		if s.includedInFilter(frontendModel) {
			lsm.Frontends = append(lsm.Frontends, frontendModel)
		}

	}

	return lsm, nil
}

func (s *LoadbalancerClient) includedInFilter(frontendModel LoadbalancerStatusModelFrontend) bool {
	if s.params.FrontendNamespace != "" && frontendModel.Namespace != s.params.FrontendNamespace {
		return false
	}

	if s.params.FrontendName != "" && frontendModel.Name != s.params.FrontendName {
		return false
	}

	if s.params.FrontendVIP != "" && frontendModel.VIP != s.params.FrontendVIP {
		return false
	}

	if s.params.FrontendPort != 0 && frontendModel.Port != s.params.FrontendPort {
		return false
	}

	if s.params.FrontendStatus != "" && frontendModel.Status != s.params.FrontendStatus {
		return false
	}

	return true
}

func (s *LoadbalancerClient) getType(frontend isovalentv1alpha1.LBFrontend) string {
	switch {
	case frontend.Spec.Applications.HTTPProxy != nil:
		return "HTTP Proxy"
	case frontend.Spec.Applications.HTTPSProxy != nil:
		return "HTTPS Proxy"
	case frontend.Spec.Applications.TLSPassthrough != nil:
		return "TLS Passthrough"
	}

	return "N/A"
}

func (s *LoadbalancerClient) getVIP(frontend isovalentv1alpha1.LBFrontend) string {
	if frontend.Status.Addresses.IPv4 != nil {
		return *frontend.Status.Addresses.IPv4
	}

	return "N/A"
}

func (s *LoadbalancerClient) getBGPPeerStatus(frontend isovalentv1alpha1.LBFrontend, nodeBGPRoutes map[string][]*models.BgpRoute, nodeBGPPeers map[string][]*models.BgpPeer) LoadbalancerStatusModelSimpleStatus {
	if frontend.Status.Addresses.IPv4 == nil {
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
			if br.Prefix == *frontend.Status.Addresses.IPv4+"/32" {
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

func (s *LoadbalancerClient) getBGPNodeStatus(frontend isovalentv1alpha1.LBFrontend, nodeBGPRoutes map[string][]*models.BgpRoute) LoadbalancerStatusModelSimpleStatus {
	if frontend.Status.Addresses.IPv4 == nil {
		return LoadbalancerStatusModelSimpleStatus{
			Status: "N/A",
			OK:     0,
			Total:  0,
		}
	}

	nrOk := 0

	for _, r := range nodeBGPRoutes {
		for _, br := range r {
			if br.Prefix == *frontend.Status.Addresses.IPv4+"/32" {
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

func (s *LoadbalancerClient) getT1Status(frontend isovalentv1alpha1.LBFrontend, nodeServices map[string][]*models.Service) LoadbalancerStatusModelSimpleStatus {
	if frontend.Status.Addresses.IPv4 == nil {
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
				s.Status.Realized.Flags.Name == "lbfe-"+frontend.Name &&
				s.Status.Realized.FrontendAddress.IP == *frontend.Status.Addresses.IPv4 &&
				s.Status.Realized.FrontendAddress.Port == uint16(frontend.Spec.Port) {

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

func (s *LoadbalancerClient) getHCT1T2(frontend isovalentv1alpha1.LBFrontend, nodeServices map[string][]*models.Service) LoadbalancerStatusModelSimpleStatus {
	if frontend.Status.Addresses.IPv4 == nil {
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
				s.Status.Realized.Flags.Name == "lbfe-"+frontend.Name &&
				s.Status.Realized.FrontendAddress.IP == *frontend.Status.Addresses.IPv4 &&
				s.Status.Realized.FrontendAddress.Port == uint16(frontend.Spec.Port) {

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

func (s *LoadbalancerClient) getT2Status(frontend isovalentv1alpha1.LBFrontend, nodeEnvoyConfigs map[string]*EnvoyConfigModel) LoadbalancerStatusModelSimpleStatus {
	if frontend.Status.Addresses.IPv4 == nil {
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
					if l.Name == fmt.Sprintf("%s/lbfe-%s/frontend_listener", frontend.Namespace, frontend.Name) &&
						l.ActiveState.Listener.Address.SocketAddress.Address == *frontend.Status.Addresses.IPv4 &&
						l.ActiveState.Listener.Address.SocketAddress.PortValue == int(frontend.Spec.Port) {
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
					if strings.HasPrefix(r.RouteConfig.Name, fmt.Sprintf("%s/lbfe-%s/", frontend.Namespace, frontend.Name)) {
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
					if strings.HasPrefix(c.Cluster.Name, fmt.Sprintf("%s/lbfe-%s/", frontend.Namespace, frontend.Name)) {
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
					if strings.HasPrefix(e.EndpointConfig.ClusterName, fmt.Sprintf("%s/lbfe-%s/", frontend.Namespace, frontend.Name)) {
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

func (s *LoadbalancerClient) getHCT2Backends(frontend isovalentv1alpha1.LBFrontend, nodeEnvoyConfigs map[string]*EnvoyConfigModel) LoadbalancerStatusModelSimpleStatus {
	if frontend.Status.Addresses.IPv4 == nil {
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
					if strings.HasPrefix(e.EndpointConfig.ClusterName, fmt.Sprintf("%s/lbfe-%s/", frontend.Namespace, frontend.Name)) {
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

func (s *LoadbalancerClient) getBackends(frontend isovalentv1alpha1.LBFrontend, nodeEnvoyConfigs map[string]*EnvoyConfigModel) LoadbalancerStatusModelGroupedStatus {
	if frontend.Status.Addresses.IPv4 == nil {
		return LoadbalancerStatusModelGroupedStatus{
			Status: "N/A",
		}
	}

	status := map[string]map[string]int{}

	for _, ecn := range nodeEnvoyConfigs {
		for _, c := range ecn.Configs {
			switch c.Type {
			case "type.googleapis.com/envoy.admin.v3.EndpointsConfigDump":
				// default/lbfe-lb-1/backend_cluster_https_0
				for _, e := range c.DynamicEndpointConfigs {
					if strings.HasPrefix(e.EndpointConfig.ClusterName, fmt.Sprintf("%s/lbfe-%s/", frontend.Namespace, frontend.Name)) {
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

	total := 0
	totalOk := 0

	groups := []LoadbalancerStatusModelSimpleStatus{}

	for _, endpoints := range status {
		nrOk := 0
		for _, v := range endpoints {
			total++
			if v == len(nodeEnvoyConfigs) {
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

func (s *LoadbalancerClient) getOverallStatus(frontend isovalentv1alpha1.LBFrontend, nodeBGPRoutes map[string][]*models.BgpRoute) string {
	if frontend.Status.Addresses.IPv4 == nil {
		return "OFFLINE"
	}

	nrOk := 0

	for _, r := range nodeBGPRoutes {
		for _, br := range r {
			if br.Prefix == *frontend.Status.Addresses.IPv4+"/32" {
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
