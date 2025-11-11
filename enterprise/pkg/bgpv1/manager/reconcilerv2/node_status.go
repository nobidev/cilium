// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/time"
)

// NodeStatus holds operational status of the local node.
type NodeStatus uint32

const (
	// NodeReady represents status of a node that is running normally.
	NodeReady NodeStatus = iota

	// NodeMaintenance represents status of a node that is in maintenance mode,
	// after making it unschedulable by "kubectl drain" command.
	NodeMaintenance

	// NodeMaintenanceTimeExpired represents status of a node that has been in maintenance mode
	// for more than the configured time.
	NodeMaintenanceTimeExpired
)

// NodeStatusProvider provides operational status of the local node.
type NodeStatusProvider interface {
	GetNodeStatus() NodeStatus
}

// NodeStatusReconciler reconciles local node k8s resource and provides its current status via GetNodeStatus() method.
type NodeStatusReconciler struct {
	logger *slog.Logger

	config   Config
	signaler *signaler.BGPCPSignaler

	localNodeStore resource.Store[*slimcorev1.Node]

	initialized          atomic.Bool
	nodeStatus           atomic.Uint32
	nodeMaintenanceTimer *time.Timer
}

type NodeStatusReconcilerOut struct {
	cell.Out

	NSProvider NodeStatusProvider
}

type NodeStatusReconcilerIn struct {
	cell.In

	Logger   *slog.Logger
	JobGroup job.Group

	Config    Config
	BGPConfig config.Config
	Signaler  *signaler.BGPCPSignaler

	LocalNodeResource k8s.LocalNodeResource
}

func NewNodeStatusReconciler(params NodeStatusReconcilerIn) NodeStatusReconcilerOut {
	if !params.BGPConfig.Enabled {
		return NodeStatusReconcilerOut{}
	}

	r := &NodeStatusReconciler{
		logger:   params.Logger.With(types.ReconcilerLogField, "NodeStatus"),
		config:   params.Config,
		signaler: params.Signaler,
	}

	if !params.Config.MaintenanceGracefulShutdownEnabled && params.Config.MaintenanceWithdrawTime == 0 {
		// no need to track node events, will always report node as ready
		r.nodeStatus.Store(uint32(NodeReady))
		return NodeStatusReconcilerOut{NSProvider: r}
	}

	// Set the initial state to maintenance mode, so that we do not advertise the routes unexpectedly
	// upon node restart while the node status is not known, or it is in the maintenance mode.
	if params.Config.MaintenanceWithdrawTime > 0 {
		r.nodeStatus.Store(uint32(NodeMaintenanceTimeExpired))
	} else {
		r.nodeStatus.Store(uint32(NodeMaintenance))
	}

	// init local node store
	params.JobGroup.Add(job.OneShot("init-node-store", func(ctx context.Context, health cell.Health) error {
		store, err := params.LocalNodeResource.Store(ctx)
		if err != nil {
			return fmt.Errorf("failed to create local node resource store: %w", err)
		}
		r.localNodeStore = store
		r.initialized.Store(true)
		return nil
	}))

	// handle local node events
	params.JobGroup.Add(job.Observer("handle-node-event", r.handleNodeEvent, params.LocalNodeResource))

	return NodeStatusReconcilerOut{NSProvider: r}
}

// GetNodeStatus returns current operational status of the local node.
func (r *NodeStatusReconciler) GetNodeStatus() NodeStatus {
	return NodeStatus(r.nodeStatus.Load())
}

func (r *NodeStatusReconciler) handleNodeEvent(ctx context.Context, event resource.Event[*slimcorev1.Node]) error {
	if !r.initialized.Load() {
		event.Done(fmt.Errorf("not yet initialized"))
		return nil
	}
	defer event.Done(nil)

	if event.Kind == resource.Delete || event.Object == nil {
		return nil
	}
	nodes := r.localNodeStore.List()
	if len(nodes) == 0 {
		return nil // local node not yet available
	}

	r.syncNode(ctx, nodes[0]) // LocalNodeResource should only contain local node
	return nil
}

func (r *NodeStatusReconciler) syncNode(ctx context.Context, node *slimcorev1.Node) {
	if nodeIsUnschedulable(node) {
		if NodeStatus(r.nodeStatus.Load()) == NodeReady {
			r.logger.Info("Local node is now under maintenance")
			r.nodeStatus.Store(uint32(NodeMaintenance))
			r.signaler.Event(struct{}{})

			if r.config.MaintenanceWithdrawTime > 0 {
				r.nodeMaintenanceTimer = time.NewTimer(r.config.MaintenanceWithdrawTime)
				go func() {
					select {
					case <-r.nodeMaintenanceTimer.C:
						// change status to NodeMaintenanceTimeExpired only if still in NodeMaintenance
						if r.nodeStatus.CompareAndSwap(uint32(NodeMaintenance), uint32(NodeMaintenanceTimeExpired)) {
							r.signaler.Event(struct{}{})
						}
					case <-ctx.Done():
						return
					}
				}()
			}
		}
	} else {
		if NodeStatus(r.nodeStatus.Load()) != NodeReady {
			r.logger.Info("Local node is no longer under maintenance")
			r.nodeStatus.Store(uint32(NodeReady))
			r.signaler.Event(struct{}{})

			if r.nodeMaintenanceTimer != nil {
				r.nodeMaintenanceTimer.Stop()
			}
		}
	}
}

// nodeIsUnschedulable returns true if the provided node is not schedulable, which can be achieved by "kubectl cordon"
func nodeIsUnschedulable(node *slimcorev1.Node) bool {
	for _, taint := range node.Spec.Taints {
		if taint.Key == corev1.TaintNodeUnschedulable && taint.Effect == slimcorev1.TaintEffectNoSchedule {
			return true
		}
	}
	return false
}
