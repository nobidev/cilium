// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package gobgp

import (
	"context"
	"errors"
	"fmt"

	gobgp "github.com/osrg/gobgp/v3/api"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
)

func (g *GoBGPServer) GetRoutesExtended(ctx context.Context, r *types.GetRoutesExtendedRequest) (*types.GetRoutesExtendedResponse, error) {
	var (
		routes []*types.ExtendedRoute
	)

	tt, err := toGoBGPTableType(r.TableType)
	if err != nil {
		return nil, fmt.Errorf("invalid table type: %w", err)
	}

	family := &gobgp.Family{
		Afi:  gobgp.Family_Afi(r.Family.Afi),
		Safi: gobgp.Family_Safi(r.Family.Safi),
	}

	var neighbor string
	if r.Neighbor.IsValid() {
		neighbor = r.Neighbor.String()
	}

	req := &gobgp.ListPathRequest{
		TableType: tt,
		Family:    family,
		Name:      neighbor,
	}

	var errs error

	err = g.server.ListPath(ctx, req, func(destination *gobgp.Destination) {
		paths, err := ToAgentPathsExtended(destination.Paths)
		if err != nil {
			errs = errors.Join(errs, err)
			return
		}
		routes = append(routes, &types.ExtendedRoute{
			Prefix: destination.Prefix,
			Paths:  paths,
		})
	})
	if err != nil {
		errs = errors.Join(errs, err)
	}

	// We may return partial results along with an error. This is a safe
	// guard to avoid one bad route preventing the entire route listing.
	return &types.GetRoutesExtendedResponse{
		Routes: routes,
	}, errs
}
