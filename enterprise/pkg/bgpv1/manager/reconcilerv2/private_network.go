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
	"maps"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/utils"
	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	privnetConfig "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/types"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

type PrivateNetworkReconcilerIn struct {
	cell.In

	Lifecycle cell.Lifecycle
	JobGroup  job.Group
	Logger    *slog.Logger

	Cfg           Config
	BGPConfig     config.Config
	EVPNConfig    evpnConfig.Config
	PrivnetConfig privnetConfig.Config

	Signaler  *signaler.BGPCPSignaler
	Upgrader  paramUpgrader
	Adverts   *IsovalentAdvertisement
	EVPNPaths *evpnPaths

	DB                  *statedb.DB
	PrivateNetworkTable statedb.Table[tables.PrivateNetwork]
	LocalWorkloadTable  statedb.Table[*tables.LocalWorkload]
}

type PrivateNetworkReconcilerOut struct {
	cell.Out

	Reconciler reconciler.ConfigReconciler `group:"bgp-config-reconciler"`
}

type PrivateNetworkReconciler struct {
	logger     *slog.Logger
	cfg        Config
	evpnConfig evpnConfig.Config

	signaler  *signaler.BGPCPSignaler
	upgrader  paramUpgrader
	adverts   *IsovalentAdvertisement
	evpnPaths *evpnPaths

	db               *statedb.DB
	privateNetworks  statedb.Table[tables.PrivateNetwork]
	privnetWorkloads statedb.Table[*tables.LocalWorkload]

	metadata map[string]privateNetworkReconcilerMetadata
}

type privateNetworkReconcilerMetadata struct {
	vrfAdverts         VRFAdvertisements
	vrfPaths           VRFPaths
	vrfEvpnInfos       EvpnVRFInfos
	privnetEvpnSubnets PrivnetSubnets

	workloadChanges            statedb.ChangeIterator[*tables.LocalWorkload]
	workloadChangesInitialized bool
}

// EvpnVRFInfos is a map of EVPN information per BGP VRF.
// +deepequal-gen=true
type EvpnVRFInfos map[string]*EvpnVRFInfo

// PrivnetSubnetInfo holds private network subnet information.
type PrivnetSubnetInfo struct {
	EvpnEnabledSubnetsV4 []netip.Prefix
	EvpnEnabledSubnetsV6 []netip.Prefix
}

func (in *PrivnetSubnetInfo) DeepEqual(other *PrivnetSubnetInfo) bool {
	if other == nil {
		return false
	}
	return slices.Equal(in.EvpnEnabledSubnetsV4, other.EvpnEnabledSubnetsV4) &&
		slices.Equal(in.EvpnEnabledSubnetsV6, other.EvpnEnabledSubnetsV6)
}

// PrivnetSubnets is a map of privnet subnet information privnet name.
// +deepequal-gen=true
type PrivnetSubnets map[string]*PrivnetSubnetInfo

func NewPrivateNetworkReconciler(in PrivateNetworkReconcilerIn) PrivateNetworkReconcilerOut {
	if !in.BGPConfig.Enabled || !in.EVPNConfig.Enabled || !in.PrivnetConfig.Enabled {
		return PrivateNetworkReconcilerOut{}
	}

	r := &PrivateNetworkReconciler{
		logger:           in.Logger.With(types.ReconcilerLogField, PrivateNetworkReconcilerName),
		cfg:              in.Cfg,
		evpnConfig:       in.EVPNConfig,
		signaler:         in.Signaler,
		upgrader:         in.Upgrader,
		adverts:          in.Adverts,
		evpnPaths:        in.EVPNPaths,
		db:               in.DB,
		privateNetworks:  in.PrivateNetworkTable,
		privnetWorkloads: in.LocalWorkloadTable,
		metadata:         make(map[string]privateNetworkReconcilerMetadata),
	}

	in.JobGroup.Add(
		job.OneShot("private-networks-signaler", func(ctx context.Context, _ cell.Health) error {
			return utils.SignalBGPUponTableEvents(ctx, r.db, r.privateNetworks, r.signaler, nil)
		}),
	)
	in.JobGroup.Add(
		job.OneShot("private-network-workloads-signaler", func(ctx context.Context, _ cell.Health) error {
			limiter := rate.NewLimiter(100*time.Millisecond, 1) // rate-limit reconciliation triggers to 100 milliseconds
			defer limiter.Stop()
			return utils.SignalBGPUponTableEvents(ctx, r.db, r.privnetWorkloads, r.signaler, limiter)
		}),
	)

	return PrivateNetworkReconcilerOut{
		Reconciler: r,
	}
}

func (r *PrivateNetworkReconciler) Name() string {
	return PrivateNetworkReconcilerName
}

func (r *PrivateNetworkReconciler) Priority() int {
	return PrivateNetworkReconcilerPriority
}

// Init is called when a new BGP instance is being initialized.
func (r *PrivateNetworkReconciler) Init(i *instance.BGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: privnet reconciler initialization with nil BGPInstance")
	}

	r.metadata[i.Name] = privateNetworkReconcilerMetadata{
		vrfAdverts:         make(VRFAdvertisements),
		vrfPaths:           make(VRFPaths),
		vrfEvpnInfos:       make(EvpnVRFInfos),
		privnetEvpnSubnets: make(PrivnetSubnets),
	}
	return nil
}

// Cleanup is called when a new BGP instance is being removed.
func (r *PrivateNetworkReconciler) Cleanup(i *instance.BGPInstance) {
	if i != nil {
		delete(r.metadata, i.Name)
	}
}

func (r *PrivateNetworkReconciler) getMetadata(i *EnterpriseBGPInstance) privateNetworkReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *PrivateNetworkReconciler) setMetadata(i *EnterpriseBGPInstance, metadata privateNetworkReconcilerMetadata) {
	r.metadata[i.Name] = metadata
}

func (r *PrivateNetworkReconciler) Reconcile(ctx context.Context, ossParams reconciler.ReconcileParams) error {
	p, err := r.upgrader.upgrade(ossParams)
	if err != nil {
		if errors.Is(err, ErrEntNodeConfigNotFound) {
			r.logger.Debug("Enterprise node config not found yet, skipping reconciliation")
			return nil
		}
		return err
	}
	tx := r.db.ReadTxn()
	initialized, _ := r.privateNetworks.Initialized(tx)
	if !initialized {
		r.logger.Debug("Private networks table not initialized, skipping reconciliation")
		return nil
	}
	initialized, _ = r.privnetWorkloads.Initialized(tx)
	if !initialized {
		r.logger.Debug("Private networks workloads table not initialized, skipping reconciliation")
		return nil
	}

	desiredVRFAdverts, err := r.adverts.GetConfiguredVRFAdvertisements(p.DesiredConfig, v1.BGPPrivateNetworkAdvert)
	if err != nil {
		return fmt.Errorf("failed to get desired private network advertisements: %w", err)
	}
	desiredVRFEvpnInfos, privnetEvpnSubnets, err := r.getPrivnetInfos(p, p.DesiredConfig, tx)
	if err != nil {
		return fmt.Errorf("failed to populate private network EVPN info: %w", err)
	}

	// run the reconciliation
	err = r.reconcilePrivateNetworks(ctx, p, desiredVRFAdverts, desiredVRFEvpnInfos, privnetEvpnSubnets, tx)
	if err != nil {
		return fmt.Errorf("failed to reconcile private networks vrfAdverts %w", err)
	}

	// update metadata if the reconciliation was successful
	metadata := r.getMetadata(p.BGPInstance)
	metadata.vrfAdverts = desiredVRFAdverts
	metadata.vrfEvpnInfos = desiredVRFEvpnInfos
	metadata.privnetEvpnSubnets = privnetEvpnSubnets
	r.setMetadata(p.BGPInstance, metadata)
	return nil
}

// getPrivnetInfos populates private network EVPN and subnet information per BGP VRF.
func (r *PrivateNetworkReconciler) getPrivnetInfos(p EnterpriseReconcileParams, bgpConfig *v1.IsovalentBGPNodeInstance, tx statedb.ReadTxn) (EvpnVRFInfos, PrivnetSubnets, error) {
	privnetEvpnVRFInfos := make(EvpnVRFInfos)
	privnetEvpnSubnets := make(PrivnetSubnets)
	routersMAC := r.evpnPaths.GetEvpnRoutersMAC()
	if routersMAC == "" {
		return privnetEvpnVRFInfos, privnetEvpnSubnets, nil // if router's MAC is not known (yet), return empty infos - we will get a new reconcile event when it is updated
	}
	for idx, bgpVRF := range bgpConfig.VRFs {
		if bgpVRF.PrivateNetworkRef == nil {
			continue
		}
		privnet, _, found := r.privateNetworks.Get(tx, tables.PrivateNetworkByName(tables.NetworkName(bgpVRF.PrivateNetworkRef.Name)))
		if !found {
			r.logger.Debug("Private network not found, skipping", logfields.ClusterwidePrivateNetwork, bgpVRF.PrivateNetworkRef.Name)
			continue
		}
		if !privnet.VNI.IsValid() {
			r.logger.Debug("Private network does not have a VNI assigned, skipping", logfields.ClusterwidePrivateNetwork, bgpVRF.PrivateNetworkRef.Name)
			continue
		}

		// find EVPN-enabled subnets of the privnet
		evpnSubnets := r.getEVPNEnabledSubnets(privnet)
		if len(evpnSubnets.EvpnEnabledSubnetsV4) == 0 && len(evpnSubnets.EvpnEnabledSubnetsV6) == 0 {
			r.logger.Debug("No EVPN-enabled subnets in the privnet, skipping", logfields.ClusterwidePrivateNetwork, bgpVRF.PrivateNetworkRef.Name)
			continue
		}
		privnetEvpnSubnets[bgpVRF.PrivateNetworkRef.Name] = evpnSubnets

		// populate EVPN information for the privnet
		evpnInfo := &EvpnVRFInfo{
			VNI:        privnet.VNI,
			RoutersMAC: routersMAC,
		}
		if bgpVRF.RD != nil {
			evpnInfo.RD = *bgpVRF.RD
		} else {
			// Auto-derive RD.
			// We need an internal VRF ID here. We can not use VNI, since VNI is a 24-bit number and the VRF ID needs to be 16-bit.
			// As VRFs is a list, we can use VRF's index in the list as internal VRF ID - it gives us consistent ID
			// across agent restarts. The drawback is that indexes may be changed upon VRF list configuration change
			// (if new VRFs are added in between existing in the list), but that should not be a frequent use-case.
			vrfID := uint16(idx + 1)
			evpnInfo.RD = DeriveEVPNRouteDistinguisher(p.BGPInstance.Global.RouterID, vrfID)
		}
		if len(bgpVRF.ExportRTs) > 0 {
			evpnInfo.RTs = bgpVRF.ExportRTs
		} else {
			// Auto-derive RT.
			evpnInfo.RTs = []string{DeriveEVPNRouteTarget(p.BGPInstance.Global.ASN, privnet.VNI)}
		}
		privnetEvpnVRFInfos[bgpVRF.PrivateNetworkRef.Name] = evpnInfo
	}
	return privnetEvpnVRFInfos, privnetEvpnSubnets, nil
}

func (r *PrivateNetworkReconciler) getEVPNEnabledSubnets(privnet tables.PrivateNetwork) *PrivnetSubnetInfo {
	subnetInfo := &PrivnetSubnetInfo{}
	for _, subnet := range privnet.Subnets {
		v4found, v6found := false, false
		for _, route := range subnet.Routes {
			if route.EVPNGateway {
				if route.Destination.Addr().Is4() && !v4found {
					subnetInfo.EvpnEnabledSubnetsV4 = append(subnetInfo.EvpnEnabledSubnetsV4, subnet.CIDRv4)
					v4found = true
				}
				if route.Destination.Addr().Is6() && !v6found {
					subnetInfo.EvpnEnabledSubnetsV6 = append(subnetInfo.EvpnEnabledSubnetsV6, subnet.CIDRv6)
					v6found = true
				}
				if v4found && v6found {
					break // break routes loop, continue with the next subnet
				}
			}
		}
	}
	return subnetInfo
}

func (r *PrivateNetworkReconciler) reconcilePrivateNetworks(ctx context.Context, p EnterpriseReconcileParams, desiredVRFAdverts VRFAdvertisements, desiredVRFEVPN EvpnVRFInfos, evpnSubnets PrivnetSubnets, tx statedb.ReadTxn) error {
	metadata := r.getMetadata(p.BGPInstance)

	reqFullReconcile := r.configModified(p, desiredVRFAdverts, desiredVRFEVPN, evpnSubnets)
	// if workload changes iterator has not been initialized yet (first reconcile), perform full reconciliation
	if !metadata.workloadChangesInitialized {
		reqFullReconcile = true
	}

	// populate desired paths per BGP VRF / private network
	desiredVRFPaths := make(VRFPaths)

	if reqFullReconcile {
		r.logger.Debug("Full private network advertisements reconciliation")
		allWorkloads, err := r.fullReconciliationWorkloadList(p) // note: can be called only once per reconcile
		if err != nil {
			return err
		}
		for _, vrf := range p.DesiredConfig.VRFs {
			if vrf.PrivateNetworkRef == nil {
				continue
			}
			privNetName := vrf.PrivateNetworkRef.Name
			// populate paths for the workloads of this VRF / privnet
			desiredPaths, err := r.getPrivNetAFPaths(desiredVRFAdverts[privNetName], desiredVRFEVPN[privNetName], evpnSubnets[privNetName], allWorkloads[privNetName])
			if err != nil {
				return err
			}
			// mark deleted workloads of this VRF / privnet for cleanup
			for resourceKey := range metadata.vrfPaths[privNetName] {
				if _, ok := desiredPaths[resourceKey]; !ok {
					desiredPaths[resourceKey] = nil // mark resource for cleanup
				}
			}
			desiredVRFPaths[privNetName] = desiredPaths
		}
	} else {
		r.logger.Debug("Diff private network advertisements reconciliation")
		toReconcile, toWithdraw, err := r.diffReconciliationWorkloadList(p, tx) // note: can be called only once per reconcile
		if err != nil {
			return err
		}
		for _, vrf := range p.DesiredConfig.VRFs {
			if vrf.PrivateNetworkRef == nil {
				continue
			}
			privNetName := vrf.PrivateNetworkRef.Name
			// populate paths for modified workloads of this VRF / privnet
			diffPaths, err := r.getPrivNetAFPaths(desiredVRFAdverts[privNetName], desiredVRFEVPN[privNetName], evpnSubnets[privNetName], toReconcile[privNetName])
			if err != nil {
				return err
			}
			withdrawPaths := r.withdrawPrivNetAFPaths(toWithdraw[privNetName])

			// copy all existing paths to desiredPaths
			desiredPaths := make(reconciler.ResourceAFPathsMap)
			maps.Copy(desiredPaths, metadata.vrfPaths[privNetName])

			// override modified / deleted paths
			maps.Copy(desiredPaths, diffPaths)
			maps.Copy(desiredPaths, withdrawPaths)
			desiredVRFPaths[privNetName] = desiredPaths
		}
	}

	// cleanup paths for deleted BGP VRFs
	for vrf := range metadata.vrfPaths {
		if _, ok := desiredVRFAdverts[vrf]; !ok {
			desiredVRFPaths[vrf] = nil // mark VRF for cleanup
		}
	}

	return ReconcileVRFPaths(ReconcileVRFPathsParams{
		Logger:       r.logger,
		Ctx:          ctx,
		BGPInstance:  p.BGPInstance,
		CurrentPaths: r.getMetadata(p.BGPInstance).vrfPaths,
		DesiredPaths: desiredVRFPaths,
	})
}

func (r *PrivateNetworkReconciler) configModified(p EnterpriseReconcileParams, desiredAdverts VRFAdvertisements, desiredEVPNInfos EvpnVRFInfos, evpnSubnets PrivnetSubnets) bool {
	metadata := r.getMetadata(p.BGPInstance)

	return !VRFAdvertisementsEqual(metadata.vrfAdverts, desiredAdverts) ||
		(desiredEVPNInfos != nil && !desiredEVPNInfos.DeepEqual(&metadata.vrfEvpnInfos) ||
			evpnSubnets != nil && !evpnSubnets.DeepEqual(&metadata.privnetEvpnSubnets))
}

func (r *PrivateNetworkReconciler) fullReconciliationWorkloadList(p EnterpriseReconcileParams) (map[string][]*tables.LocalWorkload, error) {
	var err error
	metadata := r.getMetadata(p.BGPInstance)

	// re-init changes interator, so that it contains changes since the last full reconciliation
	tx := r.db.WriteTxn(r.privnetWorkloads)
	metadata.workloadChanges, err = r.privnetWorkloads.Changes(tx)
	if err != nil {
		tx.Abort()
		return nil, fmt.Errorf("error subscribing to private network workloads changes: %w", err)
	}
	rx := tx.Commit()
	metadata.workloadChangesInitialized = true
	r.setMetadata(p.BGPInstance, metadata)

	toReconcile := make(map[string][]*tables.LocalWorkload)

	// the initial set of changes emits all existing workloads
	events, _ := metadata.workloadChanges.Next(rx)
	for event := range events {
		w := event.Object
		privNet := w.Interface.Network
		toReconcile[privNet] = append(toReconcile[privNet], w)
	}
	return toReconcile, nil
}

func (r *PrivateNetworkReconciler) diffReconciliationWorkloadList(p EnterpriseReconcileParams, rx statedb.ReadTxn) (toReconcile, toWithdraw map[string][]*tables.LocalWorkload, err error) {
	metadata := r.getMetadata(p.BGPInstance)
	if !metadata.workloadChangesInitialized {
		return nil, nil, fmt.Errorf("BUG: private network workload changes tracker not initialized, cannot perform diff reconciliation")
	}

	toReconcile = make(map[string][]*tables.LocalWorkload)
	toWithdraw = make(map[string][]*tables.LocalWorkload)

	// list workload which changed since the last reconciliation
	events, _ := metadata.workloadChanges.Next(rx)
	for event := range events {
		w := event.Object
		privNet := w.Interface.Network
		if event.Deleted {
			toWithdraw[privNet] = append(toWithdraw[privNet], w)
		} else {
			toReconcile[privNet] = append(toReconcile[privNet], w)
		}
	}
	return
}

func (r *PrivateNetworkReconciler) getPrivNetAFPaths(desiredAdverts FamilyAdvertisements, evpnVRFInfo *EvpnVRFInfo, subnetInfo *PrivnetSubnetInfo, workloads []*tables.LocalWorkload) (reconciler.ResourceAFPathsMap, error) {
	desiredWorkloadAFPaths := make(reconciler.ResourceAFPathsMap)
	if evpnVRFInfo == nil || subnetInfo == nil {
		return desiredWorkloadAFPaths, nil
	}
	for _, w := range workloads {
		afPaths, err := r.getWorkloadAFPaths(desiredAdverts, evpnVRFInfo, subnetInfo, w)
		if err != nil {
			return nil, err
		}
		key := resource.Key{Namespace: w.Namespace, Name: w.Endpoint.Name}
		desiredWorkloadAFPaths[key] = afPaths
	}
	return desiredWorkloadAFPaths, nil
}

func (r *PrivateNetworkReconciler) withdrawPrivNetAFPaths(workloads []*tables.LocalWorkload) reconciler.ResourceAFPathsMap {
	desiredWorkloadAFPaths := make(reconciler.ResourceAFPathsMap)
	for _, w := range workloads {
		key := resource.Key{Namespace: w.Namespace, Name: w.Endpoint.Name}
		desiredWorkloadAFPaths[key] = nil // setting the path to nil will withdraw the path
	}
	return desiredWorkloadAFPaths
}

func (r *PrivateNetworkReconciler) getWorkloadAFPaths(desiredAdverts FamilyAdvertisements, evpVRFInfo *EvpnVRFInfo, subnetInfo *PrivnetSubnetInfo, w *tables.LocalWorkload) (reconciler.AFPathsMap, error) {
	desiredAFPaths := make(reconciler.AFPathsMap)
	for family := range desiredAdverts {
		agentFamily := types.ToAgentFamily(family)
		workloadAddr := ""
		if agentFamily.Afi == types.AfiIPv4 && w.Interface.Addressing.IPv4 != "" {
			workloadAddr = w.Interface.Addressing.IPv4
		} else if agentFamily.Afi == types.AfiIPv6 && w.Interface.Addressing.IPv6 != "" {
			workloadAddr = w.Interface.Addressing.IPv6
		} else {
			continue
		}
		addr, err := netip.ParseAddr(workloadAddr)
		if err != nil {
			return nil, fmt.Errorf("could not parse privnet workload address: %w", err)
		}
		if !addrInEVPNEnabledSubnet(subnetInfo, addr) {
			continue
		}
		var securityGroupID *uint16
		if r.evpnConfig.SecurityGroupTagsEnabled {
			// we support only default security group ID for now
			securityGroupID = &r.evpnConfig.DefaultSecurityGroupID
		}
		prefix := netip.PrefixFrom(addr, addr.BitLen())
		path, pathKey, err := r.evpnPaths.GetEvpnRT5Path(prefix, evpVRFInfo, securityGroupID)
		if err != nil {
			return nil, err
		}
		reconciler.AddPathToAFPathsMap(desiredAFPaths, agentFamily, path, pathKey)
	}
	return desiredAFPaths, nil
}

func addrInEVPNEnabledSubnet(subnetInfo *PrivnetSubnetInfo, addr netip.Addr) bool {
	if addr.Is4() {
		for _, cidr := range subnetInfo.EvpnEnabledSubnetsV4 {
			if cidr.Contains(addr) {
				return true
			}
		}
	} else {
		for _, cidr := range subnetInfo.EvpnEnabledSubnetsV6 {
			if cidr.Contains(addr) {
				return true
			}
		}
	}
	return false
}
