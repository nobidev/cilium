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
	"sync/atomic"

	"github.com/cilium/statedb"
	"github.com/cilium/stream"

	"github.com/cilium/cilium/enterprise/pkg/k8s/types"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	isovalent_v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
)

type policyWatcher struct {
	log         *slog.Logger
	config      *option.DaemonConfig
	clusterName string

	k8sResourceSynced *k8sSynced.Resources
	k8sAPIGroups      *k8sSynced.APIGroups

	policyImporter policycell.PolicyImporter

	db       *statedb.DB
	services statedb.Table[*loadbalancer.Service]
	backends statedb.Table[*loadbalancer.Backend]

	serviceEvents stream.Observable[serviceEvent]

	ipCache ipc

	// Number of outstanding requests still pending in the PolicyImporter
	// This is only used during initial sync; we will increment these
	// as new work is learned and decrement them as the importer makes progress.
	inpSyncPending, icnpSyncPending atomic.Int64

	isovalentNetworkPolicies            resource.Resource[*isovalent_v1.IsovalentNetworkPolicy]
	isovalentClusterwideNetworkPolicies resource.Resource[*isovalent_v1.IsovalentClusterwideNetworkPolicy]

	// inpCache contains both INPs and ICNPs, stored using a common intermediate
	// representation (*types.SlimINP). The cache is indexed on resource.Key,
	// that contains both the name and namespace of the resource, in order to
	// avoid key clashing between INPs and ICNPs.
	// The cache contains INPs and ICNPs in their "original form"
	// (i.e: pre-translation of each CIDRGroupRef to a CIDRSet).
	inpCache map[resource.Key]*types.SlimINP

	// toServicesPolicies is the set of policies that contain ToServices references
	toServicesPolicies map[resource.Key]struct{}
	inpByServiceID     map[loadbalancer.ServiceName]map[resource.Key]struct{}
}

func (p *policyWatcher) watchResources(ctx context.Context) {
	// Channels to receive results from the PolicyImporter
	// Only used during initialization
	inpDone := make(chan uint64, 100)
	icnpDone := make(chan uint64, 100)

	// Consume result channels, decrement outstanding work counter.
	go func() {
		inpDone := inpDone
		icnpDone := icnpDone
		for {
			select {
			case <-inpDone:
				if p.inpSyncPending.Add(-1) <= 0 {
					inpDone = nil
				}
			case <-icnpDone:
				if p.icnpSyncPending.Add(-1) <= 0 {
					icnpDone = nil
				}
			}
			if inpDone == nil && icnpDone == nil {
				break
			}
		}
		p.log.Info("All policy resources synchronized!")
	}()
	go func() {
		var (
			inpEvents     <-chan resource.Event[*isovalent_v1.IsovalentNetworkPolicy]
			icnpEvents    <-chan resource.Event[*isovalent_v1.IsovalentClusterwideNetworkPolicy]
			serviceEvents <-chan serviceEvent
		)
		// copy the done-channels so we can nil them here and stop sending, without
		// affecting the reader above
		inpDone := inpDone
		icnpDone := icnpDone

		inpEvents = p.isovalentNetworkPolicies.Events(ctx)
		icnpEvents = p.isovalentClusterwideNetworkPolicies.Events(ctx)
		if p.serviceEvents != nil {
			serviceEvents = stream.ToChannel(ctx, p.serviceEvents)
		}

		for {
			select {
			case event, ok := <-inpEvents:
				if !ok {
					inpEvents = nil
					break
				}

				if event.Kind == resource.Sync {
					inpDone <- 0
					inpDone = nil
					event.Done(nil)
					continue
				}

				slimINP := &types.SlimINP{
					IsovalentNetworkPolicy: &isovalent_v1.IsovalentNetworkPolicy{
						TypeMeta:   event.Object.TypeMeta,
						ObjectMeta: event.Object.ObjectMeta,
						Spec:       event.Object.Spec,
						Specs:      event.Object.Specs,
					},
				}

				resourceID := ipcacheTypes.NewResourceID(
					ipcacheTypes.ResourceKindCNP,
					slimINP.ObjectMeta.Namespace,
					slimINP.ObjectMeta.Name,
				)
				var err error
				switch event.Kind {
				case resource.Upsert:
					err = p.onUpsert(slimINP, event.Key, k8sAPIGroupIsovalentNetworkPolicyV1, resourceID, inpDone)
				case resource.Delete:
					p.onDelete(slimINP, event.Key, k8sAPIGroupIsovalentNetworkPolicyV1, resourceID, inpDone)
				}
				reportINPChangeMetrics(err)
				event.Done(err)
			case event, ok := <-icnpEvents:
				if !ok {
					icnpEvents = nil
					break
				}

				if event.Kind == resource.Sync {
					icnpDone <- 0
					icnpDone = nil
					event.Done(nil)
					continue
				}

				slimINP := &types.SlimINP{
					IsovalentNetworkPolicy: &isovalent_v1.IsovalentNetworkPolicy{
						TypeMeta:   event.Object.TypeMeta,
						ObjectMeta: event.Object.ObjectMeta,
						Spec:       event.Object.Spec,
						Specs:      event.Object.Specs,
					},
				}

				resourceID := ipcacheTypes.NewResourceID(
					ipcacheTypes.ResourceKindCCNP,
					slimINP.ObjectMeta.Namespace,
					slimINP.ObjectMeta.Name,
				)
				var err error
				switch event.Kind {
				case resource.Upsert:
					err = p.onUpsert(slimINP, event.Key, k8sAPIGroupIsovalentClusterwideNetworkPolicyV1, resourceID, icnpDone)
				case resource.Delete:
					p.onDelete(slimINP, event.Key, k8sAPIGroupIsovalentClusterwideNetworkPolicyV1, resourceID, icnpDone)
				}
				reportINPChangeMetrics(err)
				event.Done(err)
			case event, ok := <-serviceEvents:
				if !ok {
					serviceEvents = nil
					break
				}
				p.onServiceEvent(event)
			}
			if inpEvents == nil && icnpEvents == nil && serviceEvents == nil {
				return
			}
		}
	}()
}
