// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// This file originates from Ciliums's codebase and is governed by an
// Apache 2.0 license (see original header below):
//
// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/enterprise/pkg/k8s/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ipcache"
	isovalent_v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
)

const (
	k8sAPIGroupIsovalentNetworkPolicyV1            = "isovalent/v1::IsovalentNetworkPolicy"
	k8sAPIGroupIsovalentClusterwideNetworkPolicyV1 = "isovalent/v1::IsovalentClusterwideNetworkPolicy"
)

// Cell starts the K8s policy watcher. The K8s policy watcher watches all Isovalent policy related
// K8s resources (IsovalentNetworkPolicy (INP) and IsovalentClusterwideNetworkPolicy (ICNP)),
// translates them to Cilium's own policy representation (api.Rules) and updates the policy
// repository (via PolicyManager) accordingly.
var Cell = cell.Module(
	"isovalent-policy-k8s-watcher",
	"Watches Isovalent policy related K8s resources",

	// K8s resource watchers
	cell.ProvidePrivate(isovalentNetworkPolicyResource),
	cell.ProvidePrivate(isovalentClusterwideNetworkPolicyResource),

	cell.Invoke(startK8sPolicyWatcher),
)

type PolicyManager interface {
	PolicyAdd(rules api.Rules, opts *policy.AddOptions) (newRev uint64, err error)
	PolicyDelete(labels labels.LabelArray, opts *policy.DeleteOptions) (newRev uint64, err error)
}

type ipc interface {
	UpsertMetadataBatch(updates ...ipcache.MU) (revision uint64)
	RemoveMetadataBatch(updates ...ipcache.MU) (revision uint64)
}

type PolicyWatcherParams struct {
	cell.In

	Lifecycle cell.Lifecycle

	ClientSet client.Clientset
	Config    *option.DaemonConfig
	Logger    *slog.Logger

	K8sResourceSynced *synced.Resources
	K8sAPIGroups      *synced.APIGroups

	DB       *statedb.DB
	Services statedb.Table[*loadbalancer.Service]
	Backends statedb.Table[*loadbalancer.Backend]

	IPCache        *ipcache.IPCache
	PolicyImporter policycell.PolicyImporter

	IsovalentNetworkPolicies            resource.Resource[*isovalent_v1.IsovalentNetworkPolicy]
	IsovalentClusterwideNetworkPolicies resource.Resource[*isovalent_v1.IsovalentClusterwideNetworkPolicy]

	ClusterInfo             cmtypes.ClusterInfo
	ClusterMeshPolicyConfig cmtypes.PolicyConfig
}

func startK8sPolicyWatcher(params PolicyWatcherParams) {
	if !params.ClientSet.IsEnabled() {
		return // skip watcher if K8s is not enabled
	}

	// We want to subscribe before the start hook is invoked in order to not miss
	// any events
	ctx, cancel := context.WithCancel(context.Background())

	p := &policyWatcher{
		log:                                 params.Logger,
		config:                              params.Config,
		clusterName:                         cmtypes.LocalClusterNameForPolicies(params.ClusterMeshPolicyConfig, params.ClusterInfo.Name),
		policyImporter:                      params.PolicyImporter,
		k8sResourceSynced:                   params.K8sResourceSynced,
		k8sAPIGroups:                        params.K8sAPIGroups,
		db:                                  params.DB,
		services:                            params.Services,
		backends:                            params.Backends,
		ipCache:                             params.IPCache,
		isovalentNetworkPolicies:            params.IsovalentNetworkPolicies,
		isovalentClusterwideNetworkPolicies: params.IsovalentClusterwideNetworkPolicies,

		inpCache: make(map[resource.Key]*types.SlimINP),

		toServicesPolicies: make(map[resource.Key]struct{}),
		inpByServiceID:     make(map[loadbalancer.ServiceName]map[resource.Key]struct{}),
	}

	// Service notifications are not used if CNPs/CCNPs are disabled.
	if params.Config.EnableCiliumNetworkPolicy || params.Config.EnableCiliumClusterwideNetworkPolicy {
		p.serviceEvents = serviceEventStream(params.DB, params.Services, params.Backends)
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(startCtx cell.HookContext) error {
			p.watchResources(ctx)
			return nil
		},
		OnStop: func(cell.HookContext) error {
			if cancel != nil {
				cancel()
			}
			return nil
		},
	})

	p.inpSyncPending.Store(1)
	p.registerResourceWithSyncFn(ctx, k8sAPIGroupIsovalentNetworkPolicyV1, func() bool {
		return p.inpSyncPending.Load() == 0
	})

	p.icnpSyncPending.Store(1)
	p.registerResourceWithSyncFn(ctx, k8sAPIGroupIsovalentClusterwideNetworkPolicyV1, func() bool {
		return p.icnpSyncPending.Load() == 0
	})
}

func isovalentNetworkPolicyResource(lc cell.Lifecycle, cs client.Clientset, mp workqueue.MetricsProvider) (resource.Resource[*isovalent_v1.IsovalentNetworkPolicy], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*isovalent_v1.IsovalentNetworkPolicyList](cs.IsovalentV1().IsovalentNetworkPolicies("")),
	)
	return resource.New[*isovalent_v1.IsovalentNetworkPolicy](lc, lw, mp, resource.WithMetric("IsovalentNetworkPolicy")), nil
}

func isovalentClusterwideNetworkPolicyResource(lc cell.Lifecycle, cs client.Clientset, mp workqueue.MetricsProvider) (resource.Resource[*isovalent_v1.IsovalentClusterwideNetworkPolicy], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*isovalent_v1.IsovalentClusterwideNetworkPolicyList](cs.IsovalentV1().IsovalentClusterwideNetworkPolicies()),
	)
	return resource.New[*isovalent_v1.IsovalentClusterwideNetworkPolicy](lc, lw, mp, resource.WithMetric("IsovalentClusterwideNetworkPolicy")), nil
}
