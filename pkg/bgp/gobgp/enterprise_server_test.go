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
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
)

func TestAddRemoveRoutePolicyExtended(t *testing.T) {
	for _, tt := range types.TestCommonExtendedRoutePolicies {
		t.Run(tt.Name, func(t *testing.T) {
			ossRouter, err := NewGoBGPServer(context.Background(), hivetest.Logger(t), testServerParameters)
			require.NoError(t, err)
			router := ossRouter.(types.EnterpriseRouter)

			t.Cleanup(func() {
				router.Stop(context.Background(), ossTypes.StopRequest{FullDestroy: true})
			})
			gobgpServer := router.(*GoBGPServer).server

			// add testing policy
			err = router.AddRoutePolicyExtended(context.Background(), types.RoutePolicyExtendedRequest{Policy: tt.Policy})
			if !tt.Valid {
				// if error is expected, check that polices are cleaned up and return
				require.Error(t, err)
				checkPoliciesCleanedUp(t, gobgpServer)
				return
			}
			require.NoError(t, err)

			// retrieve policies
			pResp, err := router.GetRoutePoliciesExtended(context.Background())
			require.NoError(t, err)

			// ignore the global policy that is configured when starting GoBGP
			filteredPolicies := []*types.ExtendedRoutePolicy{}
			for _, policy := range pResp.Policies {
				if policy.Name == globalAllowLocalPolicyName {
					continue
				}
				filteredPolicies = append(filteredPolicies, policy)
			}
			pResp.Policies = filteredPolicies

			// check that retrieved policy matches the expected
			require.Len(t, pResp.Policies, 1)
			require.Equal(t, tt.Policy, pResp.Policies[0])

			// remove testing policy
			err = router.RemoveRoutePolicyExtended(context.Background(), types.RoutePolicyExtendedRequest{Policy: tt.Policy})
			require.NoError(t, err)

			checkPoliciesCleanedUp(t, gobgpServer)
		})
	}
}
