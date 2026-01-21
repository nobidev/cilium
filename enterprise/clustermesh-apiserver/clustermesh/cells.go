//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package clustermesh

import (
	"github.com/cilium/hive/cell"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/clustermesh-apiserver/clustermesh"
	"github.com/cilium/cilium/clustermesh-apiserver/common"
	entcmk8s "github.com/cilium/cilium/enterprise/clustermesh-apiserver/clustermesh/k8s"
	"github.com/cilium/cilium/enterprise/pkg/clustermesh/clustercfg"
	"github.com/cilium/cilium/enterprise/pkg/clustermesh/phantom"
	pncfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	iso_api_v1a1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

var (
	EnterpriseClusterMesh = cell.Module(
		"enterprise-clustermesh",
		"Cilium ClusterMesh Enterprise",

		common.Cell,
		clustermesh.Cell,

		entcmk8s.ResourcesCell,

		// Configure the enterprise-specific bits of the CiliumClusterConfig.
		clustercfg.Cell,

		// Override service converter to pre-process phantom services before
		// k8s-to-kvstore synchronization.
		phantom.Cell,

		EnterpriseSynchronization,
	)

	EnterpriseSynchronization = cell.Module(
		"enterprise-clustermesh-sync",
		"Synchronize information from Kubernetes to KVStore",

		cell.Group(
			cell.Config(pncfg.DefaultCommon),

			cell.Provide(
				func(cfg pncfg.Common) *clustercfg.PrivateNetworksCapability {
					return ptr.To(clustercfg.PrivateNetworksCapability(cfg.Enabled))
				},

				newPrivateNetworkEndpointSliceOptions,
				newPrivateNetworkEndpointSliceConverter,
				newPrivateNetworkEndpointSliceNamespacer,
			),
			cell.Invoke(clustermesh.RegisterSynchronizer[*iso_api_v1a1.PrivateNetworkEndpointSlice]),
		),
	)
)
