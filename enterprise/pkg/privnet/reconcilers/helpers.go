// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilers

import (
	"iter"

	"github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	"github.com/cilium/cilium/pkg/time"
)

// SettleTime is the time reconcilers wait before proceeding with the actual
// reconciliation, to batch work.
const SettleTime = 50 * time.Millisecond

// EndpointActivationManager allows reconcilers to mark privnet-enabled
// endpoints as active or inactive and subscribe to changes to the
// active or inactive status of an endpoint
type EndpointActivationManager struct {
	subscribers []endpointActivationSubscriber
}

func newEndpointActivationManager() *EndpointActivationManager {
	return &EndpointActivationManager{
		subscribers: []endpointActivationSubscriber{},
	}
}

type endpointActivationSubscriber interface {
	EndpointActivationChanged(endpoints.Endpoint)
}

// Subscribe is used to subscribe to changes to endpoint activation done via this manager.
// Must only be called at construction time.
func (e *EndpointActivationManager) Subscribe(subscriber endpointActivationSubscriber) {
	e.subscribers = append(e.subscribers, subscriber)
}

// SetActivatedAt sets the activatedAt timestamp of an endpoint and informs the subscribers
func (e *EndpointActivationManager) SetActivatedAt(ep endpoints.Endpoint, time time.Time) {
	ep.SetPropertyValue(endpoints.PropertyPrivNetActivatedAt, endpoints.FormatActivatedAtProperty(time))
	ep.SyncEndpointHeaderFile() // ensure the new activatedAt timestamp is persisted on disk
	for _, subscriber := range e.subscribers {
		subscriber.EndpointActivationChanged(ep)
	}
}

// watchesTracker tracks the associations between each watch channel and the
// associated list of objects. The same channel may be associated with multiple
// objects, in case they all map to the same watch channel.
type watchesTracker[T any] map[<-chan struct{}][]T

func newWatchesTracker[T any]() watchesTracker[T] {
	return make(watchesTracker[T])
}

// Register registers a watch channel to object association.
func (tracker watchesTracker[T]) Register(watch <-chan struct{}, obj T) {
	tracker[watch] = append(tracker[watch], obj)
}

// Iter returns an iterator over all objects matching one of the closed channels.
func (tracker watchesTracker[T]) Iter(closed []<-chan struct{}) iter.Seq[T] {
	return func(yield func(T) bool) {
		for _, watch := range closed {
			objs, found := tracker[watch]

			// The watch channel is not in our cache. This is expected if closed
			// includes other channels as well, such as initialization ones.
			if !found {
				continue
			}

			delete(tracker, watch)
			for _, obj := range objs {
				if !yield(obj) {
					return
				}
			}
		}
	}
}
