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

// AddRoutePolicyExtended adds a new routing policy into the global policies of the server.
func (g *GoBGPServer) AddRoutePolicyExtended(ctx context.Context, r types.RoutePolicyExtendedRequest) error {
	if r.Policy == nil {
		return fmt.Errorf("nil policy in the RoutePolicyRequest")
	}
	policy, definedSets := toGoBGPPolicyExtended(r.Policy)

	for i, ds := range definedSets {
		err := g.server.AddDefinedSet(ctx, &gobgp.AddDefinedSetRequest{DefinedSet: ds})
		if err != nil {
			g.deleteDefinedSets(ctx, definedSets[:i]) // clean up already created defined sets
			return fmt.Errorf("failed adding policy defined set %s: %w", ds.Name, err)
		}
	}

	err := g.server.AddPolicy(ctx, &gobgp.AddPolicyRequest{Policy: policy})
	if err != nil {
		g.deleteDefinedSets(ctx, definedSets) // clean up defined sets
		return fmt.Errorf("failed adding policy %s: %w", policy.Name, err)
	}

	// Note that we are using global policy assignment here (per-neighbor policies work only in the route-server mode)
	assignment := g.getGlobalPolicyAssignment(policy, r.Policy.Type, r.DefaultExportAction)
	err = g.server.AddPolicyAssignment(ctx, &gobgp.AddPolicyAssignmentRequest{Assignment: assignment})
	if err != nil {
		g.deletePolicy(ctx, policy)           // clean up policy
		g.deleteDefinedSets(ctx, definedSets) // clean up defined sets
		return fmt.Errorf("failed adding policy assignment %s: %w", assignment.Name, err)
	}

	return nil
}

// RemoveRoutePolicyExtended removes a routing policy from the global policies of the server.
func (g *GoBGPServer) RemoveRoutePolicyExtended(ctx context.Context, r types.RoutePolicyExtendedRequest) error {
	if r.Policy == nil {
		return fmt.Errorf("nil policy in the RoutePolicyRequest")
	}
	policy, definedSets := toGoBGPPolicyExtended(r.Policy)

	assignment := g.getGlobalPolicyAssignment(policy, r.Policy.Type, r.DefaultExportAction)
	err := g.server.DeletePolicyAssignment(ctx, &gobgp.DeletePolicyAssignmentRequest{Assignment: assignment})
	if err != nil {
		return fmt.Errorf("failed deleting policy assignment %s: %w", assignment.Name, err)
	}

	err = g.deletePolicy(ctx, policy)
	if err != nil {
		return err
	}

	err = g.deleteDefinedSets(ctx, definedSets)
	if err != nil {
		return err
	}

	return nil
}

// GetRoutePoliciesExtended retrieves route policies from the underlying router
func (g *GoBGPServer) GetRoutePoliciesExtended(ctx context.Context) (*types.GetRoutePoliciesExtendedResponse, error) {
	// list defined sets into a map for later use
	definedSets := make(map[string]*gobgp.DefinedSet)
	err := g.server.ListDefinedSet(ctx, &gobgp.ListDefinedSetRequest{DefinedType: gobgp.DefinedType_NEIGHBOR}, func(ds *gobgp.DefinedSet) {
		definedSets[ds.Name] = ds
	})
	if err != nil {
		return nil, fmt.Errorf("failed listing neighbor defined sets: %w", err)
	}

	err = g.server.ListDefinedSet(ctx, &gobgp.ListDefinedSetRequest{DefinedType: gobgp.DefinedType_PREFIX}, func(ds *gobgp.DefinedSet) {
		definedSets[ds.Name] = ds
	})
	if err != nil {
		return nil, fmt.Errorf("failed listing prefix defined sets: %w", err)
	}

	err = g.server.ListDefinedSet(ctx, &gobgp.ListDefinedSetRequest{DefinedType: gobgp.DefinedType_COMMUNITY}, func(ds *gobgp.DefinedSet) {
		definedSets[ds.Name] = ds
	})
	if err != nil {
		return nil, fmt.Errorf("failed listing community defined sets: %w", err)
	}

	err = g.server.ListDefinedSet(ctx, &gobgp.ListDefinedSetRequest{DefinedType: gobgp.DefinedType_LARGE_COMMUNITY}, func(ds *gobgp.DefinedSet) {
		definedSets[ds.Name] = ds
	})
	if err != nil {
		return nil, fmt.Errorf("failed listing extended community defined sets: %w", err)
	}

	// list policy assignments into a map for later use
	assignments := make(map[string]*gobgp.PolicyAssignment)
	err = g.server.ListPolicyAssignment(ctx, &gobgp.ListPolicyAssignmentRequest{}, func(a *gobgp.PolicyAssignment) {
		for _, p := range a.Policies {
			assignments[p.Name] = a
		}
	})
	if err != nil {
		return nil, fmt.Errorf("failed listing policy assignments: %w", err)
	}

	// list & convert policies
	var policies []*types.ExtendedRoutePolicy
	err = g.server.ListPolicy(ctx, &gobgp.ListPolicyRequest{}, func(p *gobgp.Policy) {
		// process only assigned policies
		if assignment, exists := assignments[p.Name]; exists {
			policies = append(policies, toAgentPolicyExtended(p, definedSets, assignment))
		}
	})
	if err != nil {
		return nil, fmt.Errorf("failed listing route policies: %w", err)
	}

	return &types.GetRoutePoliciesExtendedResponse{
		Policies: policies,
	}, nil
}
