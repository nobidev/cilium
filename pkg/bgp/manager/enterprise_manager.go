// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package manager

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
)

// GetRoutePoliciesExtended returns BGP routing policies of the specified BGP instance from underlying router.
func (m *BGPRouterManager) GetRoutePoliciesExtended(ctx context.Context, instanceName string) (map[string][]*types.ExtendedRoutePolicy, error) {
	m.RLock()
	defer m.RUnlock()

	if !m.running {
		return nil, fmt.Errorf("bgp router manager is not running")
	}

	res := make(map[string][]*types.ExtendedRoutePolicy)

	for _, i := range m.BGPInstances {
		if instanceName != "" && i.Name != instanceName {
			continue
		}
		if entRouter, ok := i.Router.(types.EnterpriseRouter); ok {
			resp, err := entRouter.GetRoutePoliciesExtended(ctx)
			if err != nil {
				return nil, err
			}
			res[i.Name] = resp.Policies
		}
	}
	return res, nil
}
