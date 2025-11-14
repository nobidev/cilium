// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package fake

import (
	"context"
	"errors"
	"net/netip"

	ceeTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
)

type EnterpriseFakeRouter struct {
	ossTypes.FakeRouter
	ResetPeersCh chan netip.Addr
}

func NewEnterpriseFakeRouter() *EnterpriseFakeRouter {
	return &EnterpriseFakeRouter{
		FakeRouter:   *ossTypes.NewFakeRouter().(*ossTypes.FakeRouter),
		ResetPeersCh: make(chan netip.Addr, 10),
	}
}

func (f *EnterpriseFakeRouter) ResetNeighbor(ctx context.Context, r ossTypes.ResetNeighborRequest) error {
	f.ResetPeersCh <- r.PeerAddress
	return nil
}

func (f *EnterpriseFakeRouter) GetRoutesExtended(ctx context.Context, r *ceeTypes.GetRoutesExtendedRequest) (*ceeTypes.GetRoutesExtendedResponse, error) {
	var errs error

	ossResp, err := f.GetRoutes(ctx, &r.GetRoutesRequest)
	if err != nil {
		errs = errors.Join(errs, err)
	}

	extendedRoutes := []*ceeTypes.ExtendedRoute{}
	for _, ossRoute := range ossResp.Routes {
		extendedRoute := &ceeTypes.ExtendedRoute{
			Prefix: ossRoute.Prefix,
		}
		for _, ossPath := range ossRoute.Paths {
			extendedPath := &ceeTypes.ExtendedPath{
				Path: *ossPath,
			}
			extendedRoute.Paths = append(extendedRoute.Paths, extendedPath)
		}
		extendedRoutes = append(extendedRoutes, extendedRoute)
	}

	return &ceeTypes.GetRoutesExtendedResponse{
		Routes: extendedRoutes,
	}, errs
}
