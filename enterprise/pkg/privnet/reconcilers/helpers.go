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
	"github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	"github.com/cilium/cilium/pkg/time"
)

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
