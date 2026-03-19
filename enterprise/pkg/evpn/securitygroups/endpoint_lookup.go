// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package securitygroups

import (
	privnetEndpoints "github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	"github.com/cilium/cilium/pkg/endpointmanager"
)

// endpointLookupProvider provides endpoint lookup API.
type endpointLookupProvider interface {
	// lookupEndpointMetadataByName looks up endpoint by name and returns endpoint ID
	// and a flag determining whether the endpoint is a privnet-enabled endpoint.
	lookupEndpointMetadataByName(name string) (id uint16, isPrivnet bool)
}

// endpointLookupAdapter implements [endpointLookupProvider] interface by calling the endpointmanager API.
type endpointLookupAdapter struct {
	lookup endpointmanager.EndpointsLookup
}

func newEndpointLookupAdapter(lookup endpointmanager.EndpointsLookup) endpointLookupProvider {
	return endpointLookupAdapter{lookup: lookup}
}

// lookupEndpointMetadataByName looks up endpoint by name and returns endpoint ID
// and a flag determining whether the endpoint as a privnet-enabled endpoint.
func (a endpointLookupAdapter) lookupEndpointMetadataByName(name string) (id uint16, isPrivnet bool) {
	ep := a.lookup.LookupCEPName(name)
	if ep == nil {
		return 0, false
	}
	id = ep.GetID16()
	_, isPrivnet = privnetEndpoints.ExtractEndpointProperties(ep)
	return
}
