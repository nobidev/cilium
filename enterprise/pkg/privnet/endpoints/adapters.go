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
	"errors"
	"iter"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointapi "github.com/cilium/cilium/pkg/endpoint/api"
	"github.com/cilium/cilium/pkg/endpointmanager"
)

// newEndpointAPIManagerAdapter creates a new endpointAPIManagerAdapter
func newEndpointAPIManagerAdapter(epam endpointapi.EndpointAPIManager) EndpointCreator {
	return endpointAPIManagerAdapter{
		epam: epam,
	}
}

// endpointAPIManagerAdapter implements EndpointCreator on top of endpointapi.EndpointAPIManager
type endpointAPIManagerAdapter struct {
	epam endpointapi.EndpointAPIManager
}

// CreateEndpoint implements EndpointCreator.
func (e endpointAPIManagerAdapter) CreateEndpoint(ctx context.Context, epTemplate *models.EndpointChangeRequest) (Endpoint, error) {
	ep, _, err := e.epam.CreateEndpoint(ctx, epTemplate)
	return ep, err
}

// newEndpointManagerAdapter creates a new endpointManagerAdapter
func newEndpointManagerAdapter(epm endpointmanager.EndpointManager) (EndpointGetter, EndpointRemover) {
	a := endpointManagerAdapter{
		epm: epm,
	}
	return a, a
}

// endpointManagerAdapter implements EndpointGetter and EndpointRemover on top of endpointmanager.EndpointManager
type endpointManagerAdapter struct {
	epm endpointmanager.EndpointManager
}

// RemoveByCEPName implements EndpointRemover.
func (e endpointManagerAdapter) RemoveByCEPName(nsname string) (Endpoint, error) {
	ep := e.epm.LookupCEPName(nsname)
	if ep == nil {
		return nil, nil
	}
	return ep, errors.Join(e.epm.RemoveEndpoint(ep, endpoint.DeleteConfig{
		NoIPRelease: ep.DatapathConfiguration.ExternalIpam,
	})...)
}

// LookupCEPName implements EndpointGetter.
func (e endpointManagerAdapter) LookupCEPName(nsname string) Endpoint {
	ep := e.epm.LookupCEPName(nsname)
	if ep == nil {
		// This is needed to avoid having the returned interface value
		// holding a nil concrete value that is itself non-nil.
		return nil
	}
	return ep
}

// GetEndpointsByPodName implements EndpointGetter.
func (e endpointManagerAdapter) GetEndpointsByPodName(nsname string) iter.Seq[Endpoint] {
	return func(yield func(Endpoint) bool) {
		eps := e.epm.GetEndpointsByPodName(nsname)
		for _, ep := range eps {
			if !yield(ep) {
				break
			}
		}
	}
}

// Subscribe implements EndpointGetter.
func (e endpointManagerAdapter) Subscribe(s EndpointSubscriber) {
	e.epm.Subscribe(endpointSubscriberAdapter{
		s: s,
	})
}

// endpointSubscriberAdapter implements EndpointSubscriber on top of endpointmanager.Subscriber
type endpointSubscriberAdapter struct {
	s EndpointSubscriber
}

// EndpointCreated implements endpointmanager.Subscriber.
func (e endpointSubscriberAdapter) EndpointCreated(ep *endpoint.Endpoint) {
	e.s.EndpointCreated(ep)
}

// EndpointDeleted implements endpointmanager.Subscriber.
func (e endpointSubscriberAdapter) EndpointDeleted(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) {
	e.s.EndpointDeleted(ep)
}

// EndpointRestored implements endpointmanager.Subscriber.
func (e endpointSubscriberAdapter) EndpointRestored(ep *endpoint.Endpoint) {
	e.s.EndpointRestored(ep)
}
