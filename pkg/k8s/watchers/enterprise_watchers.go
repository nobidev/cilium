// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"maps"

	isovalent_v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/synced"
)

const (
	k8sAPIGroupIsovalentEgressGatewayPolicyV1 = "isovalent/v1::IsovalentEgressGatewayPolicy"
)

var isovalentResourceToGroupMapping = map[string]watcherInfo{
	synced.CRDResourceName(isovalent_v1.IEGPName): {start, k8sAPIGroupIsovalentEgressGatewayPolicyV1},
}

func init() {
	maps.Copy(ciliumResourceToGroupMapping, isovalentResourceToGroupMapping)
}
