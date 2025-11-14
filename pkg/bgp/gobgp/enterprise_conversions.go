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
	"errors"
	"net/netip"

	gobgp "github.com/osrg/gobgp/v3/api"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
)

func ToAgentPathsExtended(paths []*gobgp.Path) ([]*types.ExtendedPath, error) {
	var errs error

	ps := []*types.ExtendedPath{}

	for _, path := range paths {
		p, err := ToAgentPathExtended(path)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		ps = append(ps, p)
	}

	return ps, errs
}

func ToAgentPathExtended(p *gobgp.Path) (*types.ExtendedPath, error) {
	ossPath, err := ToAgentPath(p)
	if err != nil {
		return nil, err
	}

	var neighborAddr netip.Addr
	if p.NeighborIp != "" {
		neighborAddr, err = netip.ParseAddr(p.NeighborIp)
		if err != nil {
			return nil, err
		}
	}

	return &types.ExtendedPath{
		Path:         *ossPath,
		NeighborAddr: neighborAddr,
	}, nil
}
