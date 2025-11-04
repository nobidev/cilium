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
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	enterpriseTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	ossreconcilerv2 "github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	"github.com/cilium/cilium/pkg/bgp/types"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// NeighborReconciler is a ConfigReconciler which reconciles the peers of the
// provided BGP server with the provided CiliumBGPVirtualRouter.
type NeighborReconciler struct {
	Logger           *slog.Logger
	SecretStore      store.BGPCPResourceStore[*slim_corev1.Secret]
	PeerConfig       store.BGPCPResourceStore[*v1.IsovalentBGPPeerConfig]
	Policy           store.BGPCPResourceStore[*v1.IsovalentBGPPolicy]
	EnterpriseConfig Config
	DaemonConfig     *option.DaemonConfig
	upgrader         paramUpgrader
	metadata         map[string]*NeighborReconcilerMetadata
}

type NeighborReconcilerOut struct {
	cell.Out

	Reconciler ossreconcilerv2.ConfigReconciler `group:"bgp-config-reconciler"`
}

type NeighborReconcilerIn struct {
	cell.In
	BGPConfig        config.Config
	EnterpriseConfig Config
	Logger           *slog.Logger
	SecretStore      store.BGPCPResourceStore[*slim_corev1.Secret]
	PeerConfig       store.BGPCPResourceStore[*v1.IsovalentBGPPeerConfig]
	Policy           store.BGPCPResourceStore[*v1.IsovalentBGPPolicy]
	DaemonConfig     *option.DaemonConfig
	Upgrader         paramUpgrader
}

func NewNeighborReconciler(params NeighborReconcilerIn) NeighborReconcilerOut {
	if !params.BGPConfig.Enabled {
		return NeighborReconcilerOut{}
	}

	return NeighborReconcilerOut{
		Reconciler: &NeighborReconciler{
			Logger:           params.Logger.With(types.ReconcilerLogField, "Neighbor"),
			SecretStore:      params.SecretStore,
			PeerConfig:       params.PeerConfig,
			Policy:           params.Policy,
			EnterpriseConfig: params.EnterpriseConfig,
			DaemonConfig:     params.DaemonConfig,
			upgrader:         params.Upgrader,
			metadata:         make(map[string]*NeighborReconcilerMetadata),
		},
	}
}

// PeerData keeps a peer and its configuration. It also keeps the TCP password from secret store.
// +deepequal-gen=true
// Note:  If you change PeerDate, do not forget to 'make generate-k8s-api', which will update DeepEqual method.
type PeerData struct {
	Peer     *v1.IsovalentBGPNodePeer
	Config   *v1.IsovalentBGPPeerConfigSpec
	Password string
}

// NeighborReconcilerMetadata keeps a map of running peers to peer configuration.
// Key is the peer name.
type NeighborReconcilerMetadata struct {
	Peers         map[string]*PeerData
	RoutePolicies ossreconcilerv2.RoutePolicyMap
}

func (r *NeighborReconciler) getMetadata(i *EnterpriseBGPInstance) *NeighborReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *NeighborReconciler) upsertMetadataPeer(i *EnterpriseBGPInstance, d *PeerData) {
	if i == nil || d == nil {
		return
	}
	m := r.metadata[i.Name]
	m.Peers[d.Peer.Name] = d
}

func (r *NeighborReconciler) deleteMetadataPeer(i *EnterpriseBGPInstance, d *PeerData) {
	if i == nil || d == nil {
		return
	}
	delete(r.metadata[i.Name].Peers, d.Peer.Name)
}

func (r *NeighborReconciler) upsertMetadataPolicies(i *EnterpriseBGPInstance, policies ossreconcilerv2.RoutePolicyMap) {
	if i == nil || policies == nil {
		return
	}
	r.metadata[i.Name].RoutePolicies = policies
}

func (r *NeighborReconciler) Name() string {
	return NeighborReconcilerName
}

func (r *NeighborReconciler) Priority() int {
	return NeighborReconcilerPriority
}

func (r *NeighborReconciler) Init(i *instance.BGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: %s reconciler initialization with nil BGPInstance", r.Name())
	}
	r.metadata[i.Name] = &NeighborReconcilerMetadata{
		Peers:         make(map[string]*PeerData),
		RoutePolicies: make(ossreconcilerv2.RoutePolicyMap),
	}
	return nil
}

func (r *NeighborReconciler) Cleanup(i *instance.BGPInstance) {
	if i != nil {
		delete(r.metadata, i.Name)
	}
}

func (r *NeighborReconciler) Reconcile(ctx context.Context, _p ossreconcilerv2.ReconcileParams) error {
	if _p.DesiredConfig == nil {
		return fmt.Errorf("attempted neighbor reconciliation with nil IsovalentBGPNodeInstance")
	}
	if _p.BGPInstance == nil {
		return fmt.Errorf("attempted neighbor reconciliation with nil BGPInstance")
	}

	p, err := r.upgrader.upgrade(_p)
	if err != nil {
		if errors.Is(err, ErrEntNodeConfigNotFound) {
			r.Logger.Debug("Enterprise node config not found yet, skipping reconciliation")
			return nil
		}
		return err
	}

	var (
		l = r.Logger.With(types.InstanceLogField, p.DesiredConfig.Name)

		toCreate []*PeerData
		toRemove []*PeerData
		toUpdate []*PeerData
	)
	metadata := r.getMetadata(p.BGPInstance)
	curNeigh := metadata.Peers
	newNeigh := p.DesiredConfig.Peers

	l.Debug("Begin reconciling peers")

	type member struct {
		new *PeerData
		cur *PeerData
	}

	nset := map[string]*member{}

	for i, n := range newNeigh {
		if n.PeerASN == nil {
			return fmt.Errorf("peer %s does not have a PeerASN", n.Name)
		}

		if n.PeerAddress == nil || *n.PeerAddress == "" {
			if n.AutoDiscovery != nil && n.AutoDiscovery.Mode == v1.BGPADUnnumbered {
				// If the peer is an unnumbered peer, it is possible that the PeerAddress is not yet discovered.
				l.Debug("Peer does not have PeerAddress configured yet, skipping", types.PeerLogField, n.Name)
				continue
			} else {
				// If the peer is not an unnumbered peer, it must have a PeerAddress.
				return fmt.Errorf("peer %s does not have a PeerAddress", n.Name)
			}
		}

		var (
			key = r.neighborID(&n)
			h   *member
			ok  bool
		)

		config, exists, err := r.getPeerConfig(n.PeerConfigRef)
		if err != nil {
			return err
		}
		if !exists {
			continue // configured peer config does not exist, skip
		}

		passwd, err := r.getPeerPassword(p.DesiredConfig.Name, n.Name, config)
		if err != nil {
			return err
		}

		if h, ok = nset[key]; !ok {
			nset[key] = &member{
				new: &PeerData{
					Peer:     &newNeigh[i],
					Config:   config,
					Password: passwd,
				},
			}
			continue
		}
		h.new = &PeerData{
			Peer:     &newNeigh[i],
			Config:   config,
			Password: passwd,
		}
	}

	for i, n := range curNeigh {
		var (
			key = r.neighborID(n.Peer)
			h   *member
			ok  bool
		)

		if h, ok = nset[key]; !ok {
			nset[key] = &member{
				cur: curNeigh[i],
			}
			continue
		}
		h.cur = curNeigh[i]
	}

	for _, m := range nset {
		// present in new neighbors (set new) but not in current neighbors (set cur)
		if m.new != nil && m.cur == nil {
			toCreate = append(toCreate, m.new)
		}
		// present in current neighbors (set cur) but not in new neighbors (set new)
		if m.cur != nil && m.new == nil {
			toRemove = append(toRemove, m.cur)
		}
		// present in both new neighbors (set new) and current neighbors (set cur), update if they are not equal
		if m.cur != nil && m.new != nil {
			if !m.cur.DeepEqual(m.new) {
				toUpdate = append(toUpdate, m.new)
			}
		}
	}

	if len(toCreate) > 0 || len(toRemove) > 0 || len(toUpdate) > 0 {
		l.Info("Reconciling peers for instance")
	} else {
		l.Debug("No peer changes necessary")
	}

	var selfRRRole v1.RouteReflectorRole
	if p.DesiredConfig.RouteReflector != nil {
		selfRRRole = p.DesiredConfig.RouteReflector.Role
	}

	// remove neighbors
	for _, n := range toRemove {
		l.Info("Removing peer", types.PeerLogField, n.Peer.Name)

		if err := p.BGPInstance.Router.RemoveNeighbor(ctx, toNeighbor(n.Peer, n.Config, n.Password, selfRRRole)); err != nil {
			return fmt.Errorf("failed to remove neigbhor %s from instance %s: %w", n.Peer.Name, p.DesiredConfig.Name, err)
		}
		// update metadata
		r.deleteMetadataPeer(p.BGPInstance, n)
	}

	// update neighbors
	for _, n := range toUpdate {
		l.Info("Updating peer", types.PeerLogField, n.Peer.Name)

		if err := p.BGPInstance.Router.UpdateNeighbor(ctx, toNeighbor(n.Peer, n.Config, n.Password, selfRRRole)); err != nil {
			return fmt.Errorf("failed to update neigbhor %s in instance %s: %w", n.Peer.Name, p.DesiredConfig.Name, err)
		}
		// update metadata
		r.upsertMetadataPeer(p.BGPInstance, n)
	}

	// create new neighbors
	for _, n := range toCreate {
		l.Info("Adding peer", types.PeerLogField, n.Peer.Name)

		if err := p.BGPInstance.Router.AddNeighbor(ctx, toNeighbor(n.Peer, n.Config, n.Password, selfRRRole)); err != nil {
			return fmt.Errorf("failed to add neigbhor %s in instance %s: %w", n.Peer.Name, p.DesiredConfig.Name, err)
		}
		// update metadata
		r.upsertMetadataPeer(p.BGPInstance, n)
	}

	if err := r.reconcileRouteReflectorRoutePolicies(ctx, p); err != nil {
		return fmt.Errorf("failed to reconcile route reflector route policies: %w", err)
	}

	l.Debug("Done reconciling peers")
	return nil
}

func (r *NeighborReconciler) reconcileRouteReflectorRoutePolicies(ctx context.Context, p EnterpriseReconcileParams) error {
	metadata := r.getMetadata(p.BGPInstance)

	// Route reflector is not compatible with route import
	var desiredRoutePolicies ossreconcilerv2.RoutePolicyMap
	if p.DesiredConfig.RouteReflector != nil {
		desiredRoutePolicies = getDesiredRouteReflectorPolicies(p.DesiredConfig)
	} else {
		desiredRoutePolicies = r.getDesiredUserDefinedImportPolicy(p.DesiredConfig)
	}

	updatedPolicies, err := ossreconcilerv2.ReconcileRoutePolicies(&ossreconcilerv2.ReconcileRoutePoliciesParams{
		Logger:          r.Logger,
		Ctx:             ctx,
		Router:          p.BGPInstance.Router,
		DesiredPolicies: desiredRoutePolicies,
		CurrentPolicies: metadata.RoutePolicies,
	})

	r.upsertMetadataPolicies(p.BGPInstance, updatedPolicies)

	return err
}

func getDesiredRouteReflectorPolicies(instance *v1.IsovalentBGPNodeInstance) ossreconcilerv2.RoutePolicyMap {
	desiredRoutePolicies := ossreconcilerv2.RoutePolicyMap{}

	if instance.RouteReflector == nil {
		return desiredRoutePolicies
	}

	routeReflectors := []netip.Addr{}
	clients := []netip.Addr{}
	eBGPPeers := []netip.Addr{}

	for _, peer := range instance.Peers {
		if peer.PeerAddress == nil {
			continue
		}

		addr, err := netip.ParseAddr(*peer.PeerAddress)
		if err != nil {
			continue
		}

		if peer.RouteReflector != nil {
			switch peer.RouteReflector.Role {
			case v1.RouteReflectorRoleRouteReflector:
				routeReflectors = append(routeReflectors, addr)
			case v1.RouteReflectorRoleClient:
				clients = append(clients, addr)
			}
		} else if peer.PeerASN != nil && instance.LocalASN != nil && (*peer.PeerASN != *instance.LocalASN) {
			// Record non-RR eBGP peers
			eBGPPeers = append(eBGPPeers, addr)
		}
	}

	slices.SortFunc(routeReflectors, func(a, b netip.Addr) int {
		return a.Compare(b)
	})
	slices.SortFunc(clients, func(a, b netip.Addr) int {
		return a.Compare(b)
	})

	switch instance.RouteReflector.Role {
	case v1.RouteReflectorRoleRouteReflector:
		if len(routeReflectors) > 0 {
			// RR allows all imports from RR
			name := "rr-rr-allow-all-imports-from-rr"
			desiredRoutePolicies[name] = &types.RoutePolicy{
				Name: name,
				Type: types.RoutePolicyTypeImport,
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: types.RoutePolicyConditions{
							MatchNeighbors: routeReflectors,
						},
						Actions: types.RoutePolicyActions{
							RouteAction: types.RoutePolicyActionAccept,
						},
					},
				},
			}
		}

		if len(clients) > 0 {
			// RR allows all imports from clients
			name := "rr-rr-allow-all-imports-from-clients"
			desiredRoutePolicies[name] = &types.RoutePolicy{
				Name: name,
				Type: types.RoutePolicyTypeImport,
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: types.RoutePolicyConditions{
							MatchNeighbors: clients,
						},
						Actions: types.RoutePolicyActions{
							RouteAction: types.RoutePolicyActionAccept,
						},
					},
				},
			}
		}

		// RR allows all exports to any peers
		if len(clients) != 0 || len(routeReflectors) != 0 {
			name := "rr-rr-allow-all-exports"
			policy := &types.RoutePolicy{
				Name:       name,
				Type:       types.RoutePolicyTypeExport,
				Statements: []*types.RoutePolicyStatement{},
			}

			if len(eBGPPeers) > 0 {
				// For all eBGP peers, advertise routes
				// without modifying nexthop. Since
				// this doesn't care if the nexthop is
				// in the same L2 or not, the
				// advertised routes may or may not
				// work depending on the network
				// topology.
				policy.Statements = append(policy.Statements,
					&types.RoutePolicyStatement{
						Conditions: types.RoutePolicyConditions{
							MatchNeighbors: eBGPPeers,
						},
						Actions: types.RoutePolicyActions{
							RouteAction: types.RoutePolicyActionAccept,
							NextHop: &types.RoutePolicyActionNextHop{
								Unchanged: true,
							},
						},
					},
				)
			}

			policy.Statements = append(policy.Statements,
				&types.RoutePolicyStatement{
					Conditions: types.RoutePolicyConditions{},
					Actions: types.RoutePolicyActions{
						RouteAction: types.RoutePolicyActionAccept,
					},
				},
			)

			desiredRoutePolicies[name] = policy
		}

		// We still don't allow imports from non-route-reflector peers with the default import policy.
	case v1.RouteReflectorRoleClient:
		if len(routeReflectors) > 0 {
			// Client allows all imports from RR
			name := "rr-client-allow-all-imports-from-rr"
			desiredRoutePolicies[name] = &types.RoutePolicy{
				Name: name,
				Type: types.RoutePolicyTypeImport,
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: types.RoutePolicyConditions{
							MatchNeighbors: routeReflectors,
						},
						Actions: types.RoutePolicyActions{
							RouteAction: types.RoutePolicyActionAccept,
						},
					},
				},
			}
		}
		// We already allow all generated routes per neighbor. No need to add additional policies.
	}
	return desiredRoutePolicies
}

func (r *NeighborReconciler) getDesiredUserDefinedImportPolicy(instance *v1.IsovalentBGPNodeInstance) ossreconcilerv2.RoutePolicyMap {
	desiredPolicies := ossreconcilerv2.RoutePolicyMap{}

	// Feature disabled
	if !r.EnterpriseConfig.RouteImportEnabled {
		return desiredPolicies
	}

	for _, peer := range instance.Peers {
		if peer.PeerAddress == nil {
			// No PeerAddress, cannot create policy
			continue
		}

		if peer.PeerConfigRef == nil {
			// No PeerConfig, no import policy
			continue
		}

		if peer.RouteReflector != nil {
			// Route reflector is not compatible with route import
			continue
		}

		peerAddr, err := netip.ParseAddr(*peer.PeerAddress)
		if err != nil {
			// Invalid PeerAddress, skip
			continue
		}

		peerConfig, exists, err := r.getPeerConfig(peer.PeerConfigRef)
		if err != nil || !exists {
			// Cannot fetch PeerConfig, skip
			continue
		}

		for _, family := range peerConfig.Families {
			if family.ImportPolicyRef == nil {
				// No import policy reference defined
				continue
			}

			if (family.Afi != "ipv4" && family.Afi != "ipv6") || family.Safi != "unicast" {
				// We only support ipv4-unicast and ipv6-unicast families at this point
				continue
			}

			policy, exists, err := r.Policy.GetByKey(resource.Key{Name: family.ImportPolicyRef.Name})
			if err != nil || !exists {
				// Cannot fetch policy, skip
				continue
			}

			if err := enterpriseTypes.ValidateAndDefaultImportPolicy(&policy.Spec.Import, family.CiliumBGPFamily); err != nil {
				// Invalid import policy, skip
				r.Logger.Error("Skipping import policy for peer due to validation error", logfields.Error, err)
				continue
			}

			policyName := "import-user-defined-" + peer.Name + "-" + family.Afi + "-" + family.Safi

			routePolicy := enterpriseTypes.ToRoutePolicy(
				&policy.Spec.Import,
				policyName,
				peerAddr,
				types.ToAgentFamily(family.CiliumBGPFamily),
			)

			desiredPolicies[policyName] = routePolicy
		}
	}

	return desiredPolicies
}

// getPeerConfig returns the CiliumBGPPeerConfigSpec for the given peerConfig.
// If peerConfig is not specified, returns the default config.
// If the referenced peerConfig does not exist, exists returns false.
func (r *NeighborReconciler) getPeerConfig(peerConfig *v1.PeerConfigReference) (conf *v1.IsovalentBGPPeerConfigSpec, exists bool, err error) {
	if peerConfig == nil || peerConfig.Name == "" {
		// if peer config is not specified, return default config
		conf = &v1.IsovalentBGPPeerConfigSpec{}
		conf.SetDefaults()
		return conf, true, nil
	}

	config, exists, err := r.PeerConfig.GetByKey(resource.Key{Name: peerConfig.Name})
	if err != nil || !exists {
		return nil, exists, err
	}

	conf = config.Spec.DeepCopy() // copy to not ever modify config in store in SetDefaults()
	conf.SetDefaults()
	return conf, true, nil
}

func (r *NeighborReconciler) getPeerPassword(instanceName, peerName string, config *v1.IsovalentBGPPeerConfigSpec) (string, error) {
	if config == nil {
		return "", nil
	}

	if config.AuthSecretRef != nil {
		secretRef := *config.AuthSecretRef

		secret, ok, err := r.fetchSecret(secretRef)
		if err != nil {
			return "", fmt.Errorf("failed to fetch secret %q: %w", secretRef, err)
		}
		if !ok {
			return "", nil
		}
		tcpPassword := string(secret["password"])
		if tcpPassword == "" {
			return "", fmt.Errorf("failed to fetch secret %q: missing password key", secretRef)
		}
		r.Logger.Debug("Using TCP password from secret",
			types.SecretRefLogField, secretRef,
			types.InstanceLogField, instanceName,
			types.PeerLogField, peerName,
		)
		return tcpPassword, nil
	}
	return "", nil
}

func (r *NeighborReconciler) fetchSecret(name string) (map[string][]byte, bool, error) {
	if r.SecretStore == nil {
		return nil, false, fmt.Errorf("SecretsNamespace not configured")
	}
	item, ok, err := r.SecretStore.GetByKey(resource.Key{Namespace: r.DaemonConfig.BGPSecretsNamespace, Name: name})
	if err != nil || !ok {
		return nil, ok, err
	}
	result := map[string][]byte{}
	for k, v := range item.Data {
		result[k] = []byte(v)
	}
	return result, true, nil
}

func (r *NeighborReconciler) neighborID(n *v1.IsovalentBGPNodePeer) string {
	return fmt.Sprintf("%s%s%d", n.Name, *n.PeerAddress, *n.PeerASN)
}
