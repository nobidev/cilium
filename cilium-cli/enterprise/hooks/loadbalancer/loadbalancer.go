// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"context"
	"fmt"
	"slices"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	enterpriseK8s "github.com/cilium/cilium/cilium-cli/enterprise/hooks/k8s"
)

// Parameters contains options for CLI
type Parameters struct {
	WaitDuration   time.Duration
	Output         string
	RelationOutput string

	ServiceNamespace string
	ServiceName      string
	ServiceVIP       string
	ServicePort      uint
	ServiceStatus    string
}

type LoadbalancerClient struct {
	params      Parameters
	client      *enterpriseK8s.EnterpriseClient
	t1AgentPods []*Pod
	t2AgentPods []*Pod
}

type Pod struct {
	Name      string
	Namespace string
	NodeName  string
}

func NewLoadbalancerClient(client *enterpriseK8s.EnterpriseClient, params Parameters) *LoadbalancerClient {
	return &LoadbalancerClient{
		params: params,
		client: client,
	}
}

func (s *LoadbalancerClient) InitNodeAgentPods(ctx context.Context) error {
	t1Nodes, err := s.client.ListNodes(ctx, metav1.ListOptions{LabelSelector: "service.cilium.io/node=t1"})
	if err != nil {
		return err
	}

	t1NodeNames := []string{}
	for _, t1 := range t1Nodes.Items {
		t1NodeNames = append(t1NodeNames, t1.Name)
	}

	t2Nodes, err := s.client.ListNodes(ctx, metav1.ListOptions{LabelSelector: "service.cilium.io/node=t2"})
	if err != nil {
		return err
	}

	t2NodeNames := []string{}
	for _, t2 := range t2Nodes.Items {
		t2NodeNames = append(t2NodeNames, t2.Name)
	}

	agentPods, err := s.client.ListPods(ctx, "kube-system", metav1.ListOptions{LabelSelector: "k8s-app=cilium"})
	if err != nil {
		return fmt.Errorf("failed to list agent pods: %w", err)
	}

	t1AgentPods := []*Pod{}
	t2AgentPods := []*Pod{}

	for _, ap := range agentPods.Items {
		if slices.Contains(t1NodeNames, ap.Spec.NodeName) {
			t1AgentPods = append(t1AgentPods, &Pod{
				Name:      ap.Name,
				Namespace: ap.Namespace,
				NodeName:  ap.Spec.NodeName,
			})
		} else if slices.Contains(t2NodeNames, ap.Spec.NodeName) {
			t2AgentPods = append(t2AgentPods, &Pod{
				Name:      ap.Name,
				Namespace: ap.Namespace,
				NodeName:  ap.Spec.NodeName,
			})
		}
	}

	s.t1AgentPods = t1AgentPods
	s.t2AgentPods = t2AgentPods

	return nil
}

func (s *LoadbalancerClient) GetT1NodeAgentPods() []*Pod {
	return s.t1AgentPods
}

func (s *LoadbalancerClient) GetT2NodeAgentPods() []*Pod {
	return s.t2AgentPods
}
