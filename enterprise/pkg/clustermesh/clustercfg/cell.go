//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package clustercfg

import (
	"github.com/cilium/hive/cell"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
)

// PrivateNetworksCapability is the type to be provided to configure the
// private networks capability.
type PrivateNetworksCapability bool

// ClusterConfigDecorator configures the enterprise-specific bits of the CiliumClusterConfig.
var Cell = cell.DecorateAll(
	func(in cmtypes.CiliumClusterConfig, params struct {
		cell.In

		PrivateNetworks *PrivateNetworksCapability `optional:"true"`
	}) cmtypes.CiliumClusterConfig {
		in.Capabilities.PrivateNetworksEnabled = (*bool)(params.PrivateNetworks)
		return in
	},
)
