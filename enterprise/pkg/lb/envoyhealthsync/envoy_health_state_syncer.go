// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoyhealthsync

import (
	"context"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/time"
)

// Cell is responsible to sync the per-node health state of Envoy with the K8s node taint.
// If the Node is unschedulable, Envoys healthchecks should fail and draining should be initiated.
var Cell = cell.Module(
	"loadbalancer-envoy-health",
	"Syncs per-node health state of Envoy with the K8s node taint",

	cell.Invoke(registerEnvoyHealthStateSyncer),
	cell.Config(envoyHealthStateSyncerConfig{
		LoadbalancerEnvoyHealthStateSyncEnabled:  false,
		LoadbalancerEnvoyHealthStateSyncInterval: 1 * time.Minute,
	}),
)

type envoyHealthStateSyncerConfig struct {
	LoadbalancerEnvoyHealthStateSyncEnabled  bool
	LoadbalancerEnvoyHealthStateSyncInterval time.Duration
}

func (c envoyHealthStateSyncerConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("loadbalancer-envoy-health-state-sync-enabled", c.LoadbalancerEnvoyHealthStateSyncEnabled, "Enables LB health state sync between K8s node and the node-local Envoy proxy")
	flags.Duration("loadbalancer-envoy-health-state-sync-interval", c.LoadbalancerEnvoyHealthStateSyncInterval, "Interval for the periodic (fallback) LB health state sync between K8s node and the node-local Envoy proxy")
}

type healthcheckStatusSyncerParams struct {
	cell.In

	Config envoyHealthStateSyncerConfig

	JobGroup job.Group

	EnvoyAdminClient  *envoy.EnvoyAdminClient
	LocalNodeResource k8s.LocalNodeResource
}

// envoyHealthStateSyncer syncs
type envoyHealthStateSyncer struct {
	params healthcheckStatusSyncerParams
}

func registerEnvoyHealthStateSyncer(params healthcheckStatusSyncerParams) {
	if !params.Config.LoadbalancerEnvoyHealthStateSyncEnabled {
		return
	}

	syncer := envoyHealthStateSyncer{params: params}

	// Automatic sync on k8s node event
	params.JobGroup.Add(job.Observer("node-event-sync", syncer.HandleNodeEvent, params.LocalNodeResource))

	// Periodic sync as fallback (e.g. if restarting Envoy)
	params.JobGroup.Add(job.Timer("periodic-sync", syncer.Sync, params.Config.LoadbalancerEnvoyHealthStateSyncInterval))
}

func (r *envoyHealthStateSyncer) HandleNodeEvent(ctx context.Context, event resource.Event[*slim_corev1.Node]) error {
	var err error
	defer event.Done(err)

	if event.Kind == resource.Delete || event.Object == nil {
		return nil
	}

	// update err to mark the event as done with the correct error
	err = r.sync(ctx, event.Object)

	return err
}

func (r *envoyHealthStateSyncer) Sync(ctx context.Context) error {
	store, err := r.params.LocalNodeResource.Store(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve node store: %w", err)
	}

	nodes := store.List()

	if len(nodes) == 0 {
		// local node not yet available
		return nil
	}

	// use first node - LocalNodeResource should only contain local node anyway
	return r.sync(ctx, nodes[0])
}

func (r *envoyHealthStateSyncer) sync(ctx context.Context, node *slim_corev1.Node) error {
	envoyNodeState := "ok"
	if r.nodeIsUnschedulable(node) {
		envoyNodeState = "fail"
	}

	if _, err := r.params.EnvoyAdminClient.Post("healthcheck/" + envoyNodeState); err != nil {
		return fmt.Errorf("failed to update Envoy health state: %w", err)
	}

	return nil
}

func (r *envoyHealthStateSyncer) nodeIsUnschedulable(node *slim_corev1.Node) bool {
	for _, taint := range node.Spec.Taints {
		if taint.Key == corev1.TaintNodeUnschedulable && taint.Effect == slim_corev1.TaintEffectNoSchedule {
			return true
		}
	}

	return false
}
