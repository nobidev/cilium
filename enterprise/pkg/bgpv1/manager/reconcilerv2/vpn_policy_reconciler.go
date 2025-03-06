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
	"context"
	"fmt"
	"net/netip"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

type VPNRoutePolicyReconcilerOut struct {
	cell.Out

	Reconciler reconcilerv2.ConfigReconciler `group:"bgp-config-reconciler-v2"`
}

type VPNRoutePolicyReconcilerIn struct {
	cell.In

	Logger          logrus.FieldLogger
	Config          config.Config
	Upgrader        paramUpgrader
	PeerConfigStore resource.Resource[*v1.IsovalentBGPPeerConfig]
	Group           job.Group
}

// VPNRoutePolicyReconciler is a reconciler that configures VPNv4 related route policies:
//   - import route policy per peer allowing VPNv4 routes from adj-in to loc-rib.
//   - export route policy per peer allowing VPNv4 routes from loc-rib to adj-out.
type VPNRoutePolicyReconciler struct {
	initialized     atomic.Bool
	logger          logrus.FieldLogger
	upgrader        paramUpgrader
	peerConfigStore resource.Store[*v1.IsovalentBGPPeerConfig]
	metadata        map[string]VPNRoutePolicyMetadata
}

type VPNRoutePolicyMetadata struct {
	VPNPolicies reconcilerv2.RoutePolicyMap
}

func NewVPNRoutePolicyReconciler(in VPNRoutePolicyReconcilerIn) VPNRoutePolicyReconcilerOut {
	if !in.Config.Enabled {
		return VPNRoutePolicyReconcilerOut{}
	}

	rp := &VPNRoutePolicyReconciler{
		metadata: make(map[string]VPNRoutePolicyMetadata),
		logger:   in.Logger.WithField(types.ReconcilerLogField, "vpn-route-policy"),
		upgrader: in.Upgrader,
	}

	in.Group.Add(job.OneShot("init-vpn-route-policy", func(ctx context.Context, health cell.Health) error {
		pcs, err := in.PeerConfigStore.Store(ctx)
		if err != nil {
			return err
		}

		rp.peerConfigStore = pcs
		rp.initialized.Store(true)
		return nil
	}))

	return VPNRoutePolicyReconcilerOut{
		Reconciler: rp,
	}
}

func (r *VPNRoutePolicyReconciler) Name() string {
	return VPNRoutePolicyReconcilerName
}

func (r *VPNRoutePolicyReconciler) Priority() int {
	// This reconciler should run just before the OSS Neighbor reconciler,
	// so gobgp will already have desired VPN policies in place.
	return VPNRoutePolicyReconcilerPriority
}

func (r *VPNRoutePolicyReconciler) Init(i *instance.BGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: %s reconciler initialization with nil BGPInstance", r.Name())
	}
	r.metadata[i.Name] = VPNRoutePolicyMetadata{
		VPNPolicies: make(reconcilerv2.RoutePolicyMap),
	}
	return nil
}

func (r *VPNRoutePolicyReconciler) Cleanup(i *instance.BGPInstance) {
	if i != nil {
		delete(r.metadata, i.Name)
	}
}

func (r *VPNRoutePolicyReconciler) Reconcile(ctx context.Context, p reconcilerv2.ReconcileParams) error {
	if !r.initialized.Load() {
		r.logger.Debug("Not initialized yet, skipping VPN route policy reconciliation")
		return nil
	}

	if p.DesiredConfig == nil {
		return fmt.Errorf("BUG: passed nil desired config to VPN route policy reconciler")
	}

	iParams, err := r.upgrader.upgrade(p)
	if err != nil {
		return err
	}

	desiredPolicies, err := r.getDesiredRoutePolicies(iParams.DesiredConfig)
	if err != nil {
		return err
	}

	updatedPolicies, err := reconcilerv2.ReconcileRoutePolicies(&reconcilerv2.ReconcileRoutePoliciesParams{
		Logger: r.logger.WithFields(
			logrus.Fields{
				types.InstanceLogField: p.DesiredConfig.Name,
			},
		),
		Ctx:             ctx,
		Router:          p.BGPInstance.Router,
		DesiredPolicies: desiredPolicies,
		CurrentPolicies: r.GetMetadata(iParams.BGPInstance).VPNPolicies,
	})

	r.SetMetadata(iParams.BGPInstance, VPNRoutePolicyMetadata{
		VPNPolicies: updatedPolicies,
	})

	return err
}

func (r *VPNRoutePolicyReconciler) getDesiredRoutePolicies(desiredConfig *v1.IsovalentBGPNodeInstance) (reconcilerv2.RoutePolicyMap, error) {
	desiredPolicies := make(reconcilerv2.RoutePolicyMap)

	for _, peer := range desiredConfig.Peers {
		// get peer address
		peerAddr, peerAddrExists, err := GetPeerAddressFromConfig(desiredConfig, peer.Name)
		if err != nil {
			return nil, err
		}
		if !peerAddrExists {
			return nil, nil
		}

		// get the peer config
		if peer.PeerConfigRef == nil {
			r.logger.WithField(types.PeerLogField, peer.Name).Debug("Peer config reference not set, skipping peer for import policy inspection")
			continue
		}

		peerConfig, exists, err := r.peerConfigStore.GetByKey(resource.Key{Name: peer.PeerConfigRef.Name})
		if err != nil {
			return nil, err
		}

		if !exists {
			r.logger.WithField(types.PeerLogField, peer.Name).Debug("Peer config not found, skipping peer for import policy inspection")
			continue
		}

		// allow importing routes from peers which have ipv4-l3vpn family configured
		vpnPeer := false
		for _, fam := range peerConfig.Spec.Families {
			agentFamily := toAgentFamily(fam.CiliumBGPFamily)
			if agentFamily.Afi == types.AfiIPv4 && agentFamily.Safi == types.SafiMplsVpn {
				vpnPeer = true
				break
			}
		}

		if vpnPeer {
			// import route policy allowing VPNv4 routes from adj-in to loc-rib
			importPolicyName := fmt.Sprintf("%s-import-%s", r.Name(), peer.Name)
			desiredPolicies[importPolicyName] = acceptRoutePolicy(types.RoutePolicyTypeImport, importPolicyName, peerAddr)

			// export route policy allowing all VPNv4 routes from  loc-rib to adj-out
			exportPolicyName := fmt.Sprintf("%s-export-%s", r.Name(), peer.Name)
			desiredPolicies[exportPolicyName] = acceptRoutePolicy(types.RoutePolicyTypeExport, exportPolicyName, peerAddr)
		}
	}

	return desiredPolicies, nil
}

func acceptRoutePolicy(policyType types.RoutePolicyType, name string, peerAddr netip.Addr) *types.RoutePolicy {
	// create /32 or /128 prefix from peer address
	peerPrefix := netip.PrefixFrom(peerAddr, peerAddr.BitLen())

	return &types.RoutePolicy{
		Name: name,
		Type: policyType,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{peerPrefix.String()},
					MatchFamilies: []types.Family{
						{
							Afi:  types.AfiIPv4,
							Safi: types.SafiMplsVpn,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction: types.RoutePolicyActionAccept,
				},
			},
		},
	}
}

func (r *VPNRoutePolicyReconciler) GetMetadata(i *EnterpriseBGPInstance) VPNRoutePolicyMetadata {
	return r.metadata[i.Name]
}

func (r *VPNRoutePolicyReconciler) SetMetadata(i *EnterpriseBGPInstance, m VPNRoutePolicyMetadata) {
	r.metadata[i.Name] = m
}
