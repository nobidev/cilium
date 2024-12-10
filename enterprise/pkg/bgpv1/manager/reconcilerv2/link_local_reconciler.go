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
	"net/netip"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	ossreconcilerv2 "github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	osstypes "github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

type LinkLocalReconcilerIn struct {
	cell.In
	JobGroup  job.Group
	Logger    logrus.FieldLogger
	BGPConfig config.Config
	Signaler  *signaler.BGPCPSignaler
	Upgrader  paramUpgrader

	DB            *statedb.DB
	NeighborTable statedb.Table[*tables.Neighbor]
	DeviceTable   statedb.Table[*tables.Device]
}

type LinkLocalReconcilerOut struct {
	cell.Out

	Reconciler ossreconcilerv2.ConfigReconciler `group:"bgp-config-reconciler-v2"`
}

type LinkLocalReconciler struct {
	logger   logrus.FieldLogger
	signaler *signaler.BGPCPSignaler
	upgrader paramUpgrader

	db            *statedb.DB
	neighborTable statedb.Table[*tables.Neighbor]
	deviceTable   statedb.Table[*tables.Device]

	metadata map[string]LinkLocalReconcilerMetadata

	// instancesWithUnnumberedPeers is used to count the instances with unnumbered peers.
	// Used to not trigger unnecessary reconciliation events upon neighbor table changes
	// if there is no unnumbered peer configured for this node.
	instancesWithUnnumberedPeers atomic.Int32
}

type LinkLocalReconcilerMetadata struct {
	hasUnnumberedPeers bool              // used to mark if unnumbered peers are used for this instance
	linkLocalNeighbors map[string]string // cache of interface to link-local neighbor addresses
}

func NewLinkLocalReconciler(params LinkLocalReconcilerIn) LinkLocalReconcilerOut {
	if !params.BGPConfig.Enabled {
		return LinkLocalReconcilerOut{}
	}
	logger := params.Logger.WithField(osstypes.ReconcilerLogField, "LinkLocal")

	r := &LinkLocalReconciler{
		logger:        logger,
		signaler:      params.Signaler,
		upgrader:      params.Upgrader,
		db:            params.DB,
		neighborTable: params.NeighborTable,
		deviceTable:   params.DeviceTable,
		metadata:      make(map[string]LinkLocalReconcilerMetadata),
	}

	params.JobGroup.Add(
		job.OneShot("neighbor-events", func(ctx context.Context, health cell.Health) (err error) {
			return r.processStateDBNeighborEvents(ctx)
		}),
	)

	return LinkLocalReconcilerOut{
		Reconciler: r,
	}
}

func (r *LinkLocalReconciler) Name() string {
	return LinkLocalReconcilerName
}

func (r *LinkLocalReconciler) Priority() int {
	return LinkLocalReconcilerPriority
}

func (r *LinkLocalReconciler) Init(i *instance.BGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: %s reconciler initialization with nil BGPInstance", r.Name())
	}
	r.metadata[i.Name] = LinkLocalReconcilerMetadata{
		hasUnnumberedPeers: false,
		linkLocalNeighbors: make(map[string]string),
	}
	return nil
}

func (r *LinkLocalReconciler) Cleanup(i *instance.BGPInstance) {
	if i != nil {
		if r.metadata[i.Name].hasUnnumberedPeers {
			r.instancesWithUnnumberedPeers.Add(-1)
		}
		delete(r.metadata, i.Name)
	}
}

func (r *LinkLocalReconciler) Reconcile(ctx context.Context, p ossreconcilerv2.ReconcileParams) error {
	iParams, err := r.upgrader.upgrade(p)
	if err != nil {
		if errors.Is(err, NotInitializedErr) {
			r.logger.Debug("Initialization is not done, skipping Link Local reconciliation")
			return nil
		}
		return err
	}

	metadata := r.getMetadata(iParams.BGPInstance)

	if r.hasUnnumberedPeer(iParams.DesiredConfig) {
		if !metadata.hasUnnumberedPeers {
			// if we are not yet processing statedb neighbor events, start from now
			r.instancesWithUnnumberedPeers.Add(1)
			metadata.hasUnnumberedPeers = true
		}
		// update peer address in BGPNodeInstance's DesiredConfig for unnumbered peers
		err = r.updateUnnumberedPeerAddresses(iParams, p, &metadata)
	} else {
		// no unnumbered peers configured for this instance
		if metadata.hasUnnumberedPeers {
			// if we were processing statedb neighbor events, stop from now
			r.instancesWithUnnumberedPeers.Add(-1)
			metadata.hasUnnumberedPeers = false
		}
	}

	r.setMetadata(iParams.BGPInstance, metadata)
	return err
}

func (r *LinkLocalReconciler) getMetadata(i *EnterpriseBGPInstance) LinkLocalReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *LinkLocalReconciler) setMetadata(i *EnterpriseBGPInstance, m LinkLocalReconcilerMetadata) {
	r.metadata[i.Name] = m
}

func (r *LinkLocalReconciler) hasUnnumberedPeer(nodeInstance *v1alpha1.IsovalentBGPNodeInstance) bool {
	for _, peer := range nodeInstance.Peers {
		if peer.Interface != nil {
			return true
		}
	}
	return false
}

// updateUnnumberedPeerAddresses sets the peer address in BGPNodeInstance's DesiredConfig for unnumbered peers.
// PeerAddress is then referenced from various other reconcilers.
func (r *LinkLocalReconciler) updateUnnumberedPeerAddresses(iParams EnterpriseReconcileParams, oParams ossreconcilerv2.ReconcileParams, metadata *LinkLocalReconcilerMetadata) error {
	l := r.logger.WithField(osstypes.InstanceLogField, iParams.DesiredConfig.Name)
	txn := r.db.ReadTxn()

	for i, peer := range iParams.DesiredConfig.Peers {
		if peer.Interface != nil {
			peerLog := l.WithFields(logrus.Fields{osstypes.PeerLogField: peer.Name, types.InterfaceLogField: *peer.Interface})

			peerAddress, found, err := r.getIPv6LinkLocalNeighborAddress(txn, *peer.Interface)
			if err != nil {
				// The error is most likely due to non-existing interface or multiple link-local peers on the link.
				// As these are related to the host's state rather than the BGP CP, just emit a warning and skip
				// this peer. Whenever this situation is recovered on the host, we get a new reconcile thanks
				// to watching the host's neighbor table.
				peerLog.WithError(err).Warning("Failed to get link local address for the peer")
				continue
			}
			if !found {
				// Try to look up the peer address in the reconciler's metadata cache.
				// If the LL peer address was known previously and the neighbor entry was deleted after it
				// (e.g. router/link went down temporarily, or neighbor table was flushed manually to debug an issue),
				// we keep the previously set peer address, so that the BGP peer remains configured.
				// We will leave it upto BGP keepalive mechanism to manage the peering state.
				// If the LL address changes, the peering will be reconfigured as soon as we get a new neighbor entry for it.
				peerAddress, found = metadata.linkLocalNeighbors[*peer.Interface]
				if !found {
					// The LL address is not in the neighbor table nor in the cache - we skip this peer
					// (it will not be configured on the underlying router instance by the neighbor reconciler).
					peerLog.Debug("Link-local address for the peer not found")
					continue
				}
			}
			peerLog.Debugf("Setting peer address to %s", peerAddress)

			// update address in the cache
			metadata.linkLocalNeighbors[*peer.Interface] = peerAddress

			// update the peer address in CEE desired config
			iParams.DesiredConfig.Peers[i].PeerAddress = &peerAddress

			// find the peer in the OSS desired config and update the peer address
			for j, p := range oParams.DesiredConfig.Peers {
				if p.Name == peer.Name {
					oParams.DesiredConfig.Peers[j].PeerAddress = &peerAddress
					break
				}
			}
		}
	}

	return nil
}

// getIPv6LinkLocalNeighborAddress attempts to find d single neighbor with a link-local IPv6 address.
// If found, returns its link-local address with zone.
func (r *LinkLocalReconciler) getIPv6LinkLocalNeighborAddress(txn statedb.ReadTxn, ifName string) (peerAddr string, found bool, err error) {
	device, _, found := r.deviceTable.Get(txn, tables.DeviceNameIndex.Query(ifName))
	if !found {
		// configured device not found on the node - return an error
		return "", false, fmt.Errorf("device %s not found", ifName)
	}

	// try to find single neighbor with a link-local IPv6 address
	neighbors := r.neighborTable.List(txn, tables.NeighborLinkIndex.Query(device.Index))
	cnt := 0
	addr := netip.Addr{}
	for neighbor := range neighbors {
		// NOTE: unfortunately, we can not rely on the NTF_ROUTER flag here, as the netlink library does not
		// deliver a neighbor update if flags on an existing neighbor entry change. Because of that, we may miss
		// the NTF_ROUTER flag if the neighbor entry was already existing before receiving a Router Advertisement.
		if neighbor.IPAddr.Is6() && neighbor.IPAddr.IsLinkLocalUnicast() && neighbor.State&tables.NUD_FAILED == 0 {
			addr = neighbor.IPAddr
			cnt++
		}
	}

	if cnt == 0 {
		// no valid link-local neighbor found
		return "", false, nil
	} else if cnt > 1 {
		// more than one link-local neighbor found, not supported - return an error
		return "", false, fmt.Errorf("found %d link-local neighbors, only one is supported", cnt)
	}

	// single neighbor with a link-local IPv6 address found
	return addr.WithZone(ifName).String(), true, nil
}

// processStateDBNeighborEvents processes all statedb events in the "neighbor" table and triggers
// BGP reconciliation upon updates of link-local neighbor entries.
func (r *LinkLocalReconciler) processStateDBNeighborEvents(ctx context.Context) error {
	observable := statedb.Observable[*tables.Neighbor](r.db, r.neighborTable)
	ch := stream.ToChannel[statedb.Change[*tables.Neighbor]](ctx, observable)

	for ev := range ch {
		if r.instancesWithUnnumberedPeers.Load() < 1 {
			continue // do not process neighbor events if there is no unnumbered BGP peer config used on this node
		}
		neighbor := ev.Object
		if neighbor.IPAddr.Is6() && neighbor.IPAddr.IsLinkLocalUnicast() {
			r.logger.WithFields(logrus.Fields{
				types.LinkIndexLogField: neighbor.LinkIndex,
				osstypes.PeerLogField:   neighbor.IPAddr,
				"deleted":               ev.Deleted,
			}).Debug("Link-local neighbor update, triggering BGP reconciliation")
			r.signaler.Event(struct{}{})
		}
	}
	return nil
}
