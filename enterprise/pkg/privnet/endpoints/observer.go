//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package endpoints

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/enterprise/pkg/privnet/observers"
	"github.com/cilium/cilium/pkg/endpointstate"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/promise"
)

// endpointObserverEnabler is the type to requesting endpoint events may be observed
type endpointObserverEnabler bool

// EnableEndpointEventObserver allows consumers of the observable to register their
// interest in endpoint events. If no consumer enables the EndpointEventObserver,
// it will be nil.
func EnableEndpointEventObserver[T any](fn func(T) bool) cell.Cell {
	return cell.Provide(func(cfg T) (out struct {
		cell.Out
		Enabler endpointObserverEnabler `group:"privnet-observe-endpoint-events"`
	}) {
		out.Enabler = endpointObserverEnabler(fn(cfg))
		return out
	})
}

// newEndpointEventObserver creates a new EndpointEventObserver based on Cilium Monitor events
// and the restorer promise.
func newEndpointEventObserver(in struct {
	cell.In

	MonitorAgent    monitorAgent.Agent
	JobGroup        job.Group
	RestorerPromise promise.Promise[endpointstate.Restorer]

	Enablers []endpointObserverEnabler `group:"privnet-observe-endpoint-events"`
}) EndpointEventObserver {
	enabled := false
	for _, enabler := range in.Enablers {
		enabled = enabled || bool(enabler)
	}
	if !enabled {
		return nil
	}

	observer := observers.NewGeneric[EndpointID, EndpointEventKind]()
	in.JobGroup.Add(job.OneShot(
		"endpoint-observer-initial-regeneration-event",
		func(ctx context.Context, health cell.Health) error {
			health.OK("Waiting for initial endpoint regeneration")
			restorer, err := in.RestorerPromise.Await(ctx)
			if err != nil {
				return err
			}
			err = restorer.WaitForEndpointRestore(ctx)
			if err != nil {
				return err
			}

			health.OK("Initial endpoint regeneration done")
			observer.Queue(EndpointInitRegenAllDone, 0)
			return nil
		}),
	)

	// The monitor consumer is used to receive monitorAPI.EndpointNotification and
	// monitorAPI.EndpointRegenNotification events. The regen notification is emitted
	// as part of Endpoint.Regenerate, which means it happens before WaitForEndpointRestore
	// in the job above returns. This guarantees that any downstream observer will see
	// the EndpointRegenSuccess message for all restored endpoints before they will
	// see the EndpointInitRegenAllDone event.
	in.MonitorAgent.RegisterNewConsumer(&endpointRegenObserveAdapter{
		observer: observer,
	})
	return observer
}

// endpointRegenObserveAdapter feeds an EndpointRegenObserver on top of consumer.MonitorConsumer
type endpointRegenObserveAdapter struct {
	// We use a generic observer here, because it is crucial that none of the consumer.MonitorConsumer
	// are blocking. By queuing events into the generic observer, we ensure that events are buffered
	// and handled asynchronously.
	observer *observers.Generic[EndpointID, EndpointEventKind]
}

// NotifyAgentEvent implements consumer.MonitorConsumer
func (e *endpointRegenObserveAdapter) NotifyAgentEvent(typ int, message any) {
	if typ != monitorAPI.MessageTypeAgent {
		return
	}
	agentNotify, ok := message.(monitorAPI.AgentNotifyMessage)
	if !ok {
		return
	}
	switch n := agentNotify.Notification.(type) {
	case monitorAPI.EndpointNotification:
		if agentNotify.Type == monitorAPI.AgentNotifyEndpointCreated {
			e.observer.Queue(EndpointCreate, EndpointID(n.ID))
		} else if agentNotify.Type == monitorAPI.AgentNotifyEndpointDeleted {
			e.observer.Queue(EndpointDelete, EndpointID(n.ID))
		}
	case monitorAPI.EndpointRegenNotification:
		if agentNotify.Type == monitorAPI.AgentNotifyEndpointRegenerateSuccess {
			e.observer.Queue(EndpointRegenSuccess, EndpointID(n.ID))
		} else if agentNotify.Type == monitorAPI.AgentNotifyEndpointRegenerateFail {
			e.observer.Queue(EndpointRegenFailure, EndpointID(n.ID))
		}
	}
}

// NotifyPerfEvent implements consumer.MonitorConsumer
func (e *endpointRegenObserveAdapter) NotifyPerfEvent(data []byte, cpu int) {
	// ignored
}

// NotifyPerfEventLost implements consumer.MonitorConsumer
func (e *endpointRegenObserveAdapter) NotifyPerfEventLost(numLostEvents uint64, cpu int) {
	// ignored
}
