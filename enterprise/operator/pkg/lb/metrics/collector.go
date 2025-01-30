//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	loadbalancerStatus "github.com/cilium/cilium/enterprise/pkg/lb/status"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
)

type collectorParams struct {
	cell.In

	Config    Config
	JobGroup  job.Group
	Lifecycle cell.Lifecycle
	Logger    *slog.Logger
	Metrics   Metrics

	Client      client.Clientset
	CiliumNodes resource.Resource[*ciliumv2.CiliumNode]
	Pods        resource.Resource[*corev1.Pod]
}

type collector struct {
	metrics  *Metrics
	logger   *slog.Logger
	lbClient *loadbalancerStatus.LoadbalancerClient

	nodesCache map[string]*ciliumv2.CiliumNode
	nodeSync   chan struct{}

	podsCache map[string]*corev1.Pod
	podSync   chan struct{}

	prevUnhealthyBgpPeers              map[string]float64
	prevUnhealthyBgpNodes              map[string]float64
	prevUnhealthyT1Nodes               map[string]float64
	prevUnhealthyT2Healthchecks        map[string]float64
	prevUnhealthyT2Nodes               map[string]float64
	prevUnhealthyT2BackendHealthchecks map[string]float64
	prevUnhealthyBackendpools          map[string][]float64

	lock.Mutex
}

func registerCollector(params collectorParams) {
	if !option.Config.EnableIPv4 {
		return
	}

	if !params.Config.LoadBalancerMetricsEnabled {
		return
	}

	lbClient := loadbalancerStatus.NewLoadbalancerClient(params.Client, params.Client, params.Client.RestConfig(), loadbalancerStatus.Parameters{
		Output: "json",
	})

	collector := collector{
		metrics:  &params.Metrics,
		logger:   params.Logger,
		lbClient: lbClient,

		podsCache: map[string]*corev1.Pod{},
		podSync:   make(chan struct{}),

		nodesCache: map[string]*ciliumv2.CiliumNode{},
		nodeSync:   make(chan struct{}),

		prevUnhealthyBgpPeers:              make(map[string]float64),
		prevUnhealthyBgpNodes:              make(map[string]float64),
		prevUnhealthyT1Nodes:               make(map[string]float64),
		prevUnhealthyT2Healthchecks:        make(map[string]float64),
		prevUnhealthyT2Nodes:               make(map[string]float64),
		prevUnhealthyT2BackendHealthchecks: make(map[string]float64),
		prevUnhealthyBackendpools:          make(map[string][]float64),
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			params.JobGroup.Add(job.Observer("loadbalancer metrics node cache", collector.nodesCacheUpdater, params.CiliumNodes))
			params.JobGroup.Add(job.Observer("loadbalancer metrics pod cache", collector.podsCacheUpdater, params.Pods))
			params.JobGroup.Add(job.Timer("loadbalancer metrics collector", collector.fetchMetrics, params.Config.LoadBalancerMetricsCollectionInterval))

			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			return nil
		},
	})
}

func (c *collector) nodesCacheUpdater(context context.Context, event resource.Event[*ciliumv2.CiliumNode]) error {
	node := event.Object
	defer event.Done(nil)

	if event.Kind == resource.Sync {
		close(c.nodeSync)
		return nil
	}

	if node.Labels["service.cilium.io/node"] != "t1" &&
		node.Labels["service.cilium.io/node"] != "t2" {
		return nil
	}

	c.Lock()
	switch event.Kind {
	case resource.Upsert:
		c.nodesCache[node.Name] = node
	case resource.Delete:
		delete(c.nodesCache, node.Name)
	}
	c.Unlock()

	c.updateT1T2CiliumPods()

	return nil
}

func (c *collector) podsCacheUpdater(context context.Context, event resource.Event[*corev1.Pod]) error {
	pod := event.Object
	defer event.Done(nil)

	if event.Kind == resource.Sync {
		close(c.podSync)
		return nil
	}

	if pod.Labels["k8s-app"] != "cilium" {
		return nil
	}

	podName := fmt.Sprintf("%s_%s", pod.Namespace, pod.Name)

	c.Lock()
	switch event.Kind {
	case resource.Upsert:
		c.podsCache[podName] = pod
	case resource.Delete:
		delete(c.podsCache, podName)
	}
	c.Unlock()

	c.updateT1T2CiliumPods()

	return nil
}

func (c *collector) updateT1T2CiliumPods() {
	c.Lock()
	defer c.Unlock()

	t1NodeNames := []string{}
	t2NodeNames := []string{}

	for _, node := range c.nodesCache {
		switch node.Labels["service.cilium.io/node"] {
		case "t1":
			t1NodeNames = append(t1NodeNames, node.Name)
		case "t2":
			t2NodeNames = append(t2NodeNames, node.Name)
		case "t1-t2":
			t1NodeNames = append(t1NodeNames, node.Name)
			t2NodeNames = append(t2NodeNames, node.Name)
		}
	}

	t1AgentPods := []*loadbalancerStatus.Pod{}
	t2AgentPods := []*loadbalancerStatus.Pod{}

	for _, pod := range c.podsCache {
		lbPod := &loadbalancerStatus.Pod{
			Name:      pod.Name,
			Namespace: pod.Namespace,
			NodeName:  pod.Spec.NodeName,
		}

		if slices.Contains(t1NodeNames, pod.Spec.NodeName) {
			t1AgentPods = append(t1AgentPods, lbPod)
		} else if slices.Contains(t2NodeNames, pod.Spec.NodeName) {
			t2AgentPods = append(t2AgentPods, lbPod)
		}
	}

	c.lbClient.SetT1NodeAgentPods(t1AgentPods)
	c.lbClient.SetT2NodeAgentPods(t2AgentPods)
}

func (c *collector) fetchMetrics(ctx context.Context) error {
	c.Lock()
	defer c.Unlock()

	ctx, cancelFn := context.WithTimeout(ctx, 1*time.Minute)
	defer cancelFn()

	lsm, err := c.lbClient.GetLoadbalancerStatusModel(ctx)
	if err != nil {
		return fmt.Errorf("failed to get loadbalancer status: %w", err)
	}

	// initMetricFromPreviousState is used to initialize a new map for the current metrics collection
	// round, where all previous services with a non zero counter are explicitly initialized to 0.
	//
	// In this way we ensure to stop reporting a failing metric if the service disappears
	initMetricFromPreviousState := func(prevMetrics map[string]float64) map[string]float64 {
		metrics := map[string]float64{}
		for serviceName, prevMetric := range c.prevUnhealthyBgpPeers {
			if prevMetric != 0 {
				metrics[serviceName] = 0
			}
		}
		return metrics
	}

	unhealthyBgpPeers := initMetricFromPreviousState(c.prevUnhealthyBgpPeers)
	unhealthyBgpNodes := initMetricFromPreviousState(c.prevUnhealthyBgpNodes)
	unhealthyT1Nodes := initMetricFromPreviousState(c.prevUnhealthyT1Nodes)
	unhealthyT2Healthchecks := initMetricFromPreviousState(c.prevUnhealthyT2Healthchecks)
	unhealthyT2Nodes := initMetricFromPreviousState(c.prevUnhealthyT2Nodes)
	unhealthyT2BackendHealthchecks := initMetricFromPreviousState(c.prevUnhealthyT2BackendHealthchecks)

	unhealthyBackendpools := map[string][]float64{}
	for service, prevUnhealthyBackendpoolCounts := range c.prevUnhealthyBackendpools {
		for _, prevUnhealthyBackendpoolCount := range prevUnhealthyBackendpoolCounts {
			if prevUnhealthyBackendpoolCount != 0 {
				unhealthyBackendpools[service] = make([]float64, len(prevUnhealthyBackendpoolCounts))
				break
			}
		}
	}

	for _, service := range lsm.Services {
		serviceName := fmt.Sprintf("%s_%s", service.Namespace, service.Name)

		unhealthyBgpPeers[serviceName] = float64(service.BGPPeerStatus.Total - service.BGPPeerStatus.OK)
		unhealthyBgpNodes[serviceName] = float64(service.BGPRouteStatus.Total - service.BGPRouteStatus.OK)
		unhealthyT1Nodes[serviceName] = float64(service.T1NodeStatus.Total - service.T1NodeStatus.OK)
		unhealthyT2Healthchecks[serviceName] = float64(service.T1T2HCStatus.Total - service.T1T2HCStatus.OK)
		unhealthyT2Nodes[serviceName] = float64(service.T2NodeStatus.Total - service.T2NodeStatus.OK)
		unhealthyT2BackendHealthchecks[serviceName] = float64(service.T2BackendHCStatus.Total - service.T2BackendHCStatus.OK)
		unhealthyBackendpools[serviceName] = make([]float64, len(service.BackendpoolStatus.Groups))
		for i, backend := range service.BackendpoolStatus.Groups {
			unhealthyBackendpools[serviceName][i] = float64(backend.Total - backend.OK)
		}
	}

	exportMetrics := func(metrics map[string]float64, desc metric.Vec[metric.Gauge]) {
		for serviceName, m := range metrics {
			desc.WithLabelValues(serviceName).Set(m)
		}
	}

	exportMetrics(unhealthyBgpPeers, c.metrics.UnhealthyBgpPeers)
	exportMetrics(unhealthyBgpNodes, c.metrics.UnhealthyBgpNodes)
	exportMetrics(unhealthyT1Nodes, c.metrics.UnhealthyT1Nodes)
	exportMetrics(unhealthyT2Healthchecks, c.metrics.UnhealthyT2Healthchecks)
	exportMetrics(unhealthyT2Nodes, c.metrics.UnhealthyT2Nodes)
	exportMetrics(unhealthyT2BackendHealthchecks, c.metrics.UnhealthyT2BackendHealthchecks)
	for service, backend := range unhealthyBackendpools {
		for i, j := range backend {
			c.metrics.UnhealthyBackendpools.WithLabelValues(service, fmt.Sprintf("%d", i)).Set(j)
		}
	}

	c.prevUnhealthyBgpPeers = unhealthyBgpPeers
	c.prevUnhealthyBgpNodes = unhealthyBgpNodes
	c.prevUnhealthyT1Nodes = unhealthyT1Nodes
	c.prevUnhealthyT2Healthchecks = unhealthyT2Healthchecks
	c.prevUnhealthyT2Nodes = unhealthyT2Nodes
	c.prevUnhealthyT2BackendHealthchecks = unhealthyT2BackendHealthchecks
	c.prevUnhealthyBackendpools = unhealthyBackendpools

	return nil
}
