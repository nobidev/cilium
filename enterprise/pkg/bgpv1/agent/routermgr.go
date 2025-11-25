// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package agent

import (
	"context"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	ossTypes "github.com/cilium/cilium/pkg/bgp/agent"
)

type EnterpriseBGPRouterManager interface {
	ossTypes.BGPRouterManager

	// GetRoutePoliciesExtended returns BGP routing policies of the specified BGP instance from underlying router.
	// If BGP instance is not specified, returns the result of all instances.
	GetRoutePoliciesExtended(ctx context.Context, instance string) (map[string][]*types.ExtendedRoutePolicy, error)
}
