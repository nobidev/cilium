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
	"context"
	"log/slog"
	"maps"
	"slices"

	"github.com/cilium/hive/job"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// ciliumNodeSource implements controller-runtime' source.Source and bridges between
// Cilium CiliumNodeEvents and controller-runtime' GenericEvent.
// This way, CiliumNodeEvents can be used to trigger reconciliations.
type ciliumNodeSource struct {
	resource.Resource[*slim_corev1.Node]

	logger *slog.Logger

	synced bool
	nodes  map[string]*node

	nodeEvents chan event.GenericEvent
}

func newNodeSource(logger *slog.Logger, config Config, jobGroup job.Group, nodeResource resource.Resource[*slim_corev1.Node]) *ciliumNodeSource {
	if !config.LoadBalancerCPEnabled {
		return nil
	}

	nodeEvents := make(chan event.GenericEvent, 1024)

	ciliumNodeSource := &ciliumNodeSource{
		Resource: nodeResource,

		logger:     logger,
		nodes:      map[string]*node{},
		nodeEvents: nodeEvents,
	}

	jobGroup.Add(job.Observer("loadbalancer cp nodeevents", ciliumNodeSource.HandleEvent, nodeResource))

	return ciliumNodeSource
}

func (r *ciliumNodeSource) HandleEvent(ctx context.Context, ev resource.Event[*slim_corev1.Node]) error {
	defer ev.Done(nil)

	if !r.synced && ev.Kind != resource.Sync {
		r.logger.Debug("Skipping event - not yet synced")
		r.nodes[ev.Key.Name] = &node{
			name:      ev.Key.Name,
			addresses: ev.Object.Status.Addresses,
		}
		return nil
	}

	if ev.Kind == resource.Sync {
		r.logger.Debug("Node sync event received - forwarding node event")
		r.nodeEvents <- event.GenericEvent{Object: ev.Object}
		r.synced = true
		return nil
	}

	if ev.Kind == resource.Delete {
		r.logger.Debug("Node delete event received - forwarding node event", logfields.NodeName, ev.Key.Name)
		r.nodeEvents <- event.GenericEvent{Object: ev.Object}
		delete(r.nodes, ev.Object.Name)
		return nil
	}

	// handle upserts -> only trigger when added or addresses or labels changed
	n, exists := r.nodes[ev.Key.Name]

	if !exists || !slices.Equal(n.addresses, ev.Object.Status.Addresses) || !maps.Equal(n.labels, ev.Object.Labels) {
		r.logger.Debug("Node upsert event received with changed relevant data - forwarding node event", logfields.NodeName, ev.Key.Name)
		r.nodes[ev.Key.Name] = &node{
			name:      ev.Key.Name,
			labels:    ev.Object.Labels,
			addresses: ev.Object.Status.Addresses,
		}
		r.nodeEvents <- event.GenericEvent{Object: ev.Object}
		return nil
	}

	r.logger.Debug("Node upsert event received without changed relevant data - skip forwarding node event", logfields.NodeName, ev.Key.Name)
	return nil
}

func (r *ciliumNodeSource) ToSource(handler handler.EventHandler) source.Source {
	return source.Channel(r.nodeEvents, handler)
}

type node struct {
	name      string
	labels    map[string]string
	addresses []slim_corev1.NodeAddress
}
