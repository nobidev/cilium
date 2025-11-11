// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"fmt"
	"sort"

	"github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/types"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
)

// PolicyName returns a unique route policy name for the provided peer, family and advertisement type.
// If there a is a need for multiple route policies per advertisement type, unique resourceID can be provided.
func PolicyName(peer, family string, advertType v1.IsovalentBGPAdvertType, resourceID string) string {
	if resourceID == "" {
		return fmt.Sprintf("%s-%s-%s", peer, family, advertType)
	}
	return fmt.Sprintf("%s-%s-%s-%s", peer, family, advertType, resourceID)
}

// MergePolicies merges two route policies into a single policy, policy statements are sorted
// based on length of the first prefix in the match prefix list.
func MergePolicies(policyA, policyB *types.RoutePolicy) (*types.RoutePolicy, error) {
	// combine route policies into a single policy
	merged, err := reconciler.MergeRoutePolicies(policyA, policyB)
	if err != nil {
		return nil, err
	}

	// sort statements based on prefix length
	sort.SliceStable(merged.Statements, func(i, j int) bool {
		// sort by first prefix length, greater length first
		if len(merged.Statements[i].Conditions.MatchPrefixes) > 0 && len(merged.Statements[j].Conditions.MatchPrefixes) > 0 {
			return merged.Statements[i].Conditions.MatchPrefixes[0].PrefixLenMin > merged.Statements[j].Conditions.MatchPrefixes[0].PrefixLenMin
		}
		return false
	})

	return merged, nil
}
