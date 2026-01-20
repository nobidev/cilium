//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package reflector

import (
	"github.com/cilium/hive/cell"
	"k8s.io/utils/ptr"

	privnet "github.com/cilium/cilium/enterprise/pkg/privnet/kvstore"
	"github.com/cilium/cilium/pkg/clustermesh/kvstoremesh/reflector"
	"github.com/cilium/cilium/pkg/clustermesh/types"
)

const (
	PrivateNetworkEndpoints = "private network endpoints"
)

var Cell = cell.Group(
	cell.Provide(
		reflector.Out(reflector.NewFactory(PrivateNetworkEndpoints, privnet.EndpointsPrefix,
			reflector.WithEnabledOverride(func(cfg types.CiliumClusterConfig) bool {
				return ptr.Deref(cfg.Capabilities.PrivateNetworksEnabled, false)
			})),
		),
	),
)
