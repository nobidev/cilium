// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

type LoadbalancerStatusModel struct {
	Summary  LoadbalancerStatusModelSummary   `json:"summary,omitempty"`
	Services []LoadbalancerStatusModelService `json:"services,omitempty"`
}

type LoadbalancerStatusModelSummary struct {
	NrOfT1Nodes  int `json:"nrOfT1Nodes"`
	NrOfT2Nodes  int `json:"nrOfT2Nodes"`
	NrOfServices int `json:"nrOfServices"`
	NrOfVIPs     int `json:"nrOfVips"`
}

type LoadbalancerStatusModelService struct {
	Namespace         string                               `json:"namespace"`
	Name              string                               `json:"name"`
	VIP               string                               `json:"vip"`
	Port              uint                                 `json:"port"`
	Type              string                               `json:"type"`
	DeploymentMode    string                               `json:"deploymentMode"`
	BGPPeerStatus     LoadbalancerStatusModelSimpleStatus  `json:"bgpPeerStatus"`
	BGPNodeStatus     LoadbalancerStatusModelSimpleStatus  `json:"bgpNodeStatus"`
	T1NodeStatus      LoadbalancerStatusModelSimpleStatus  `json:"t1NodeStatus"`
	T1T2HCStatus      LoadbalancerStatusModelSimpleStatus  `json:"t1t2HealthcheckStatus"`
	T2NodeStatus      LoadbalancerStatusModelSimpleStatus  `json:"t2NodeStatus"`
	T2BackendHCStatus LoadbalancerStatusModelSimpleStatus  `json:"t2BackendHealthcheckStatus"`
	BackendpoolStatus LoadbalancerStatusModelGroupedStatus `json:"backendpoolStatus"`
	Status            string                               `json:"status"`
}

type LoadbalancerStatusModelSimpleStatus struct {
	Status string `json:"status"`
	OK     int    `json:"ok"`
	Total  int    `json:"total"`
}

type LoadbalancerStatusModelGroupedStatus struct {
	Status string                                `json:"status"`
	Groups []LoadbalancerStatusModelSimpleStatus `json:"groups"`
}
