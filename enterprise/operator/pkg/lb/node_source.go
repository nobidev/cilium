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

	"github.com/cilium/hive/job"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

// ciliumNodeSource implements controller-runtime' source.Source and bridges between
// Cilium CiliumNodeEvents and controller-runtime' GenericEvent.
// This way, CiliumNodeEvents can be used to trigger reconciliations.
type ciliumNodeSource struct {
	resource.Resource[*ciliumv2.CiliumNode]

	nodeEvents chan event.GenericEvent
}

func newNodeSource(config Config, jobGroup job.Group, nodeResource resource.Resource[*ciliumv2.CiliumNode]) *ciliumNodeSource {
	if !config.StandaloneLbEnabled {
		return nil
	}

	nodeEvents := make(chan event.GenericEvent, 1024)

	ciliumNodeSource := &ciliumNodeSource{
		Resource: nodeResource,

		nodeEvents: nodeEvents,
	}

	jobGroup.Add(job.Observer("standalone-lb nodeevents", ciliumNodeSource.HandleEvent, nodeResource))

	return ciliumNodeSource
}

func (r *ciliumNodeSource) HandleEvent(ctx context.Context, ev resource.Event[*ciliumv2.CiliumNode]) error {
	defer ev.Done(nil)
	r.nodeEvents <- event.GenericEvent{Object: ev.Object}
	return nil
}

func (r *ciliumNodeSource) ToSource(handler handler.EventHandler) source.Source {
	return source.Channel(r.nodeEvents, handler)
}
