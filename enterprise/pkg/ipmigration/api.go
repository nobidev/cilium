//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ipmigration

import (
	"github.com/cilium/hive/cell"
	"github.com/go-openapi/runtime/middleware"

	endpointrestapi "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	ipamrestapi "github.com/cilium/cilium/api/v1/server/restapi/ipam"
)

// handlerFunc implements the swagger Handle interface for a given generic type
type handlerFunc[T any] func(T) middleware.Responder

func (f handlerFunc[Params]) Handle(p Params) middleware.Responder {
	return f(p)
}

type apiInjectorParams struct {
	cell.In

	Manager *manager

	PutEP     endpointrestapi.PutEndpointIDHandler
	IPAMAlloc ipamrestapi.PostIpamHandler
}

type apiInjectorOut struct {
	cell.Out

	PutEP     endpointrestapi.PutEndpointIDHandler
	IPAMAlloc ipamrestapi.PostIpamHandler
}

// injectAPIHandlers is a decorator which takes the upstream `PUT /endpoint/{id}` and `POST /ipam` handlers and
// replaces them with calls to the wrappers in manager.handlePutEndpointID and manager.handlePostIPAM respectively.
// The original handlers are stored in the manager such that they can be called by the wrapper if needed.
func injectAPIHandlers(p apiInjectorParams) apiInjectorOut {
	// If ip-migration is disabled, do not inject any API handlers
	if p.Manager == nil {
		return apiInjectorOut{
			PutEP:     p.PutEP,
			IPAMAlloc: p.IPAMAlloc,
		}
	}

	p.Manager.putEP = p.PutEP
	p.Manager.ipamAlloc = p.IPAMAlloc
	return apiInjectorOut{
		PutEP:     handlerFunc[endpointrestapi.PutEndpointIDParams](p.Manager.handlePutEndpointID),
		IPAMAlloc: handlerFunc[ipamrestapi.PostIpamParams](p.Manager.handlePostIPAM),
	}
}
