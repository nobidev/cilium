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

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	ossreconcilerv2 "github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/option"
)

// NeighborReconciler is a ConfigReconciler which reconciles the peers of the
// provided BGP server with the provided CiliumBGPVirtualRouter.
type NeighborReconciler struct {
	Logger       logrus.FieldLogger
	SecretStore  store.BGPCPResourceStore[*slim_corev1.Secret]
	PeerConfig   store.BGPCPResourceStore[*v1alpha1.IsovalentBGPPeerConfig]
	DaemonConfig *option.DaemonConfig
	upgrader     paramUpgrader
	metadata     map[string]NeighborReconcilerMetadata
}

type NeighborReconcilerOut struct {
	cell.Out

	Reconciler ossreconcilerv2.ConfigReconciler `group:"bgp-config-reconciler-v2"`
}

type NeighborReconcilerIn struct {
	cell.In
	Logger       logrus.FieldLogger
	SecretStore  store.BGPCPResourceStore[*slim_corev1.Secret]
	PeerConfig   store.BGPCPResourceStore[*v1alpha1.IsovalentBGPPeerConfig]
	DaemonConfig *option.DaemonConfig
	Upgrader     paramUpgrader
}

func NewNeighborReconciler(params NeighborReconcilerIn) NeighborReconcilerOut {
	logger := params.Logger.WithField(types.ReconcilerLogField, "Neighbor")

	return NeighborReconcilerOut{
		Reconciler: &NeighborReconciler{
			Logger:       logger,
			SecretStore:  params.SecretStore,
			PeerConfig:   params.PeerConfig,
			DaemonConfig: params.DaemonConfig,
			upgrader:     params.Upgrader,
			metadata:     make(map[string]NeighborReconcilerMetadata),
		},
	}
}

// PeerData keeps a peer and its configuration. It also keeps the TCP password from secret store.
// +deepequal-gen=true
// Note:  If you change PeerDate, do not forget to 'make generate-k8s-api', which will update DeepEqual method.
type PeerData struct {
	Peer     *v1alpha1.IsovalentBGPNodePeer
	Config   *v1alpha1.IsovalentBGPPeerConfigSpec
	Password string
}

// NeighborReconcilerMetadata keeps a map of running peers to peer configuration.
// Key is the peer name.
type NeighborReconcilerMetadata map[string]*PeerData

func (r *NeighborReconciler) getMetadata(i *EnterpriseBGPInstance) NeighborReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *NeighborReconciler) upsertMetadata(i *EnterpriseBGPInstance, d *PeerData) {
	if i == nil || d == nil {
		return
	}
	r.metadata[i.Name][d.Peer.Name] = d
}

func (r *NeighborReconciler) deleteMetadata(i *EnterpriseBGPInstance, d *PeerData) {
	if i == nil || d == nil {
		return
	}
	delete(r.metadata[i.Name], d.Peer.Name)
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
	r.metadata[i.Name] = make(NeighborReconcilerMetadata)
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
		return err
	}

	var (
		l = r.Logger.WithFields(logrus.Fields{
			types.InstanceLogField: p.DesiredConfig.Name,
		})

		toCreate []*PeerData
		toRemove []*PeerData
		toUpdate []*PeerData
	)
	curNeigh := r.getMetadata(p.BGPInstance)
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

		if n.Interface == nil && n.PeerAddress == nil {
			// If the peer is not an unnumbered peer, it must have a PeerAddress.
			return fmt.Errorf("peer %s does not have a PeerAddress", n.Name)
		} else if n.Interface != nil && n.PeerAddress == nil {
			// If the peer is an unnumbered peer, it is possible that the PeerAddress is not yet discovered.
			l.WithField(types.PeerLogField, n.Name).Debug("Peer does not have PeerAddress configured yet, skipping")
			continue
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

	// remove neighbors
	for _, n := range toRemove {
		l.WithField(types.PeerLogField, n.Peer.Name).Info("Removing peer")

		if err := p.BGPInstance.Router.RemoveNeighbor(ctx, toNeighbor(n.Peer, n.Config, n.Password)); err != nil {
			return fmt.Errorf("failed to remove neigbhor %s from instance %s: %w", n.Peer.Name, p.DesiredConfig.Name, err)
		}
		// update metadata
		r.deleteMetadata(p.BGPInstance, n)
	}

	// update neighbors
	for _, n := range toUpdate {
		l.WithField(types.PeerLogField, n.Peer.Name).Info("Updating peer")

		if err := p.BGPInstance.Router.UpdateNeighbor(ctx, toNeighbor(n.Peer, n.Config, n.Password)); err != nil {
			return fmt.Errorf("failed to update neigbhor %s in instance %s: %w", n.Peer.Name, p.DesiredConfig.Name, err)
		}
		// update metadata
		r.upsertMetadata(p.BGPInstance, n)
	}

	// create new neighbors
	for _, n := range toCreate {
		l.WithField(types.PeerLogField, n.Peer.Name).Info("Adding peer")

		if err := p.BGPInstance.Router.AddNeighbor(ctx, toNeighbor(n.Peer, n.Config, n.Password)); err != nil {
			return fmt.Errorf("failed to add neigbhor %s in instance %s: %w", n.Peer.Name, p.DesiredConfig.Name, err)
		}
		// update metadata
		r.upsertMetadata(p.BGPInstance, n)
	}

	l.Debug("Done reconciling peers")
	return nil
}

// getPeerConfig returns the CiliumBGPPeerConfigSpec for the given peerConfig.
// If peerConfig is not specified, returns the default config.
// If the referenced peerConfig does not exist, exists returns false.
func (r *NeighborReconciler) getPeerConfig(peerConfig *v1alpha1.PeerConfigReference) (conf *v1alpha1.IsovalentBGPPeerConfigSpec, exists bool, err error) {
	if peerConfig == nil || peerConfig.Name == "" {
		// if peer config is not specified, return default config
		conf = &v1alpha1.IsovalentBGPPeerConfigSpec{}
		conf.SetDefaults()
		return conf, true, nil
	}

	config, exists, err := r.PeerConfig.GetByKey(resource.Key{Name: peerConfig.Name})
	if err != nil || !exists {
		return nil, exists, err
	}

	conf = &config.Spec
	conf.SetDefaults()
	return conf, true, nil
}

func (r *NeighborReconciler) getPeerPassword(instanceName, peerName string, config *v1alpha1.IsovalentBGPPeerConfigSpec) (string, error) {
	if config == nil {
		return "", nil
	}

	l := r.Logger.WithFields(logrus.Fields{
		types.InstanceLogField: instanceName,
		types.PeerLogField:     peerName,
	})

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
		l.Debugf("Using TCP password from secret %q", secretRef)
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

// GetPeerAddressFromConfig returns peering address for the given peer from the provided BGPNodeInstance.
// If no error is returned and "exists" is false, it means that PeerAddress is not (yet) present in peer configuration.
func GetPeerAddressFromConfig(conf *v1alpha1.IsovalentBGPNodeInstance, peerName string) (addr netip.Addr, exists bool, err error) {
	if conf == nil {
		return netip.Addr{}, false, fmt.Errorf("passed instance is nil")
	}

	for _, peer := range conf.Peers {
		if peer.Name == peerName {
			if peer.PeerAddress != nil {
				addr, err = netip.ParseAddr(*peer.PeerAddress)
				return addr, true, err
			} else {
				return netip.Addr{}, false, nil // PeerAddress not present in peer configuration
			}
		}
	}
	return netip.Addr{}, false, fmt.Errorf("peer %s not found in instance %s", peerName, conf.Name)
}

func (r *NeighborReconciler) neighborID(n *v1alpha1.IsovalentBGPNodePeer) string {
	return fmt.Sprintf("%s%s%d", n.Name, *n.PeerAddress, *n.PeerASN)
}
