// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	ciliumClientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	ciliumMetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/time"
)

// Parameters contains options for CLI
type Parameters struct {
	WaitDuration   time.Duration
	Output         string
	RelationOutput string

	CiliumNamespace  string
	ServiceNamespace string
	ServiceName      string
	ServiceVIP       string
	ServicePort      uint
	ServiceStatus    string

	Colors  bool
	Verbose bool
}

type LoadbalancerClient struct {
	params      Parameters
	client      execClient
	t1AgentPods []*Pod
	t2AgentPods []*Pod
}

type Pod struct {
	Name      string
	Namespace string
	NodeName  string
}

func NewLoadbalancerClient(k8sClient kubernetes.Interface, ciliumClient ciliumClientset.Interface, restConfig *rest.Config, params Parameters) *LoadbalancerClient {
	return &LoadbalancerClient{
		params: params,
		client: execClient{
			k8sClient:    k8sClient,
			ciliumClient: ciliumClient,
			restConfig:   restConfig,
		},
	}
}

func (s *LoadbalancerClient) InitNodeAgentPods(ctx context.Context) error {
	t1NodeNames, t2NodeNames, err := s.getLBNodes(ctx)
	if err != nil {
		return err
	}

	agentPods, err := s.client.k8sClient.CoreV1().Pods(s.params.CiliumNamespace).List(ctx, metav1.ListOptions{LabelSelector: "k8s-app=cilium"})
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
		}

		if slices.Contains(t2NodeNames, ap.Spec.NodeName) {
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

func (s *LoadbalancerClient) SetT1NodeAgentPods(pods []*Pod) {
	s.t1AgentPods = pods
}

func (s *LoadbalancerClient) SetT2NodeAgentPods(pods []*Pod) {
	s.t2AgentPods = pods
}

const (
	defaultT1Selector = "service.cilium.io/node in ( t1 , t1-t2 )"
	defaultT2Selector = "service.cilium.io/node in ( t2 , t1-t2 )"
)

func (s *LoadbalancerClient) getLBNodes(ctx context.Context) ([]string, []string, error) {
	deployments, err := s.getLBDeployments(ctx)
	if err != nil {
		return nil, nil, err
	}

	t1Selectors := []string{defaultT1Selector}
	t2Selectors := []string{defaultT2Selector}
	for i := range deployments {
		ls := deployments[i].Spec.Nodes.LabelSelectors
		if ls == nil {
			continue
		}

		t1Selectors = append(t1Selectors, matchLabelsToLabelSelectors(ls.T1.MatchLabels)...)
		t1Selectors = append(t1Selectors, matchExpressionsToLabelSelectors(ls.T1.MatchExpressions)...)
		t2Selectors = append(t2Selectors, matchLabelsToLabelSelectors(ls.T2.MatchLabels)...)
		t2Selectors = append(t2Selectors, matchExpressionsToLabelSelectors(ls.T2.MatchExpressions)...)
	}

	t1Selectors = deduplicateSlice(t1Selectors)
	t2Selectors = deduplicateSlice(t2Selectors)

	var t1NodeNames, t2NodeNames []string
	eg := errgroup.Group{}
	eg.Go(func() error {
		names, err := s.getNodeNamesBySelector(ctx, t1Selectors)
		if err != nil {
			return err
		}
		t1NodeNames = names
		return nil
	})
	eg.Go(func() error {
		names, err := s.getNodeNamesBySelector(ctx, t2Selectors)
		if err != nil {
			return err
		}
		t2NodeNames = names
		return nil
	})

	if err := eg.Wait(); err != nil {
		return nil, nil, err
	}
	return t1NodeNames, t2NodeNames, nil
}

func (s *LoadbalancerClient) getLBDeployments(ctx context.Context) ([]v1alpha1.LBDeployment, error) {
	namespaces, err := s.client.k8sClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	deployments := make([]v1alpha1.LBDeployment, 0)
	for _, ns := range namespaces.Items {
		items, err := s.client.ciliumClient.IsovalentV1alpha1().LBDeployments(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		deployments = append(deployments, items.Items...)
	}
	return deployments, nil
}

func (s *LoadbalancerClient) getNodeNamesBySelector(ctx context.Context, labelSelectors []string) ([]string, error) {
	nodeNames := make([]string, 0)
	for _, selector := range labelSelectors {
		nodes, err := s.client.k8sClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			return nil, err
		}
		for _, node := range nodes.Items {
			nodeNames = append(nodeNames, node.Name)
		}
	}
	return deduplicateSlice(nodeNames), nil
}

func matchLabelsToLabelSelectors(labelValues map[string]ciliumMetav1.MatchLabelsValue) []string {
	if len(labelValues) == 0 {
		return []string{}
	}

	selectors := make([]string, 0, len(labelValues))
	for l, v := range labelValues {
		selectors = append(selectors, labelSelectorString(l, ciliumMetav1.LabelSelectorOpIn, v))
	}
	return selectors
}

func matchExpressionsToLabelSelectors(requirements []ciliumMetav1.LabelSelectorRequirement) []string {
	if len(requirements) == 0 {
		return []string{}
	}

	selectors := make([]string, 0, len(requirements))
	for _, r := range requirements {
		selectors = append(selectors, labelSelectorString(r.Key, r.Operator, r.Values...))
	}
	return selectors
}

func labelSelectorString(key string, operator ciliumMetav1.LabelSelectorOperator, values ...string) string {
	return fmt.Sprintf("%s %s ( %s )", key, strings.ToLower(string(operator)), strings.Join(values, " , "))
}

func deduplicateSlice(s []string) []string {
	slices.Sort(s)
	return slices.Compact(s)
}
