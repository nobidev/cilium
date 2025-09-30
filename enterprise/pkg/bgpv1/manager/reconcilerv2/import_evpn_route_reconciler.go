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
	"net"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"go4.org/netipx"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/evpn"
	pnCfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/rib"
	"github.com/cilium/cilium/enterprise/pkg/vni"
	"github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/container/bitlpm"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type importEVPNRouteReconcilerIn struct {
	cell.In

	Config        config.Config
	EVPNConfig    evpn.Config
	PrivnetConfig pnCfg.Config

	Logger   *slog.Logger
	RIB      *rib.RIB
	Upgrader paramUpgrader

	DB           *statedb.DB
	PrivnetTable statedb.Table[tables.PrivateNetwork]
}

type importEVPNRouteReconcilerOut struct {
	cell.Out

	Reconciler reconciler.StateReconciler `group:"bgp-state-reconciler"`
}

type importEVPNRouteReconciler struct {
	logger   *slog.Logger
	rib      *rib.RIB
	upgrader paramUpgrader

	db           *statedb.DB
	privnetTable statedb.Table[tables.PrivateNetwork]
}

func newImportEVPNRouteReconciler(in importEVPNRouteReconcilerIn) importEVPNRouteReconcilerOut {
	if !in.Config.Enabled || !in.EVPNConfig.Enabled || !in.PrivnetConfig.Enabled {
		return importEVPNRouteReconcilerOut{}
	}

	return importEVPNRouteReconcilerOut{
		Reconciler: &importEVPNRouteReconciler{
			logger:       in.Logger.With(types.ReconcilerLogField, "ImportEVPNRoute"),
			rib:          in.RIB,
			upgrader:     in.Upgrader,
			db:           in.DB,
			privnetTable: in.PrivnetTable,
		},
	}
}

func (r *importEVPNRouteReconciler) Name() string {
	return ImportEVPNRouteReconcilerName
}

func (r *importEVPNRouteReconciler) Priority() int {
	return ImportEVPNRouteReconcilerPriority
}

func (r *importEVPNRouteReconciler) Reconcile(ctx context.Context, _p reconciler.StateReconcileParams) error {
	if initialized, _ := r.privnetTable.Initialized(r.db.ReadTxn()); !initialized {
		r.logger.Debug("PrivateNetwork table is not initialized yet, skipping reconciliation")
		return nil
	}

	p, err := r.upgrader.upgradeState(_p)
	if err != nil {
		if errors.Is(err, ErrEntNodeConfigNotFound) {
			r.logger.Debug("Enterprise node config not found yet, skipping reconciliation")
			return nil
		}
		if errors.Is(err, ErrNotInitialized) {
			r.logger.Debug("Initialization is not done, skipping reconciliation")
			return nil
		}
		if errors.Is(err, ErrUpdateConfigNotSet) {
			r.logger.Debug("Instance config not yet set, skipping reconciliation")
			return nil
		}
		return err
	}

	// Clear all RIB entries inserted by the deleted instance
	if p.DeletedInstance != "" {
		owner := ribOwnerName(p.DeletedInstance)
		r.rib.DeleteRoutesByOwner(owner)
		return nil
	}

	res, err := p.UpdatedInstance.Router.GetRoutes(
		ctx,
		&types.GetRoutesRequest{
			TableType: types.TableTypeLocRIB,
			Family: types.Family{
				Afi:  types.AfiL2VPN,
				Safi: types.SafiEvpn,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to get BGP routes: %w", err)
	}

	owner := ribOwnerName(p.DesiredConfig.Name)

	// Obtain the desired routes from BGP RIB
	desiredRoutes, err := r.desiredRoutes(
		owner,
		uint32(*p.DesiredConfig.LocalASN),
		res.Routes,
		p.DesiredConfig.VRFs,
	)
	if err != nil {
		return fmt.Errorf("failed to get desired routes: %w", err)
	}

	// Obtain the current routes from the Cilium RIB
	currentRoutes := r.rib.ListRoutes(owner)

	// Reconcile Cilium RIB
	reconcileRIB(r.rib, desiredRoutes, currentRoutes)

	return nil
}

func (r *importEVPNRouteReconciler) desiredRoutes(
	owner string,
	localASN uint32,
	bgpRoutes []*types.Route,
	bgpVRFs []v1.IsovalentBGPNodeVRF,
) (map[uint32]*bitlpm.CIDRTrie[*rib.Route], error) {
	// First parse the BGP routes to extract EVPN routes
	paths, err := r.parseRoutes(bgpRoutes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse VPN paths: %w", err)
	}

	rtxn := r.db.ReadTxn()

	desiredRoutes := map[uint32]*bitlpm.CIDRTrie[*rib.Route]{}
	for _, bgpVRF := range bgpVRFs {
		if bgpVRF.PrivateNetworkRef == nil {
			continue
		}
		pn, _, found := r.privnetTable.Get(rtxn, tables.PrivateNetworkByName(tables.NetworkName(bgpVRF.PrivateNetworkRef.Name)))
		if !found {
			continue
		}
		vrfID := uint32(pn.ID)
		routes := bitlpm.NewCIDRTrie[*rib.Route]()
		for _, path := range paths {
			if !rtMatches(path.rts, bgpVRF.ImportRTs) {
				continue
			}
			proto := rib.ProtocolIBGP
			if path.sourceASN != localASN {
				proto = rib.ProtocolEBGP
			}
			routes.Upsert(path.prefix, &rib.Route{
				Prefix:   path.prefix,
				Owner:    owner,
				Protocol: proto,
				NextHop: &rib.VXLANEncap{
					VNI:         path.vni,
					VTEPIP:      path.vtepIP,
					InnerDstMAC: path.rtmac,
				},
			})
		}
		if routes.Len() > 0 {
			desiredRoutes[vrfID] = routes
		}
	}

	return desiredRoutes, nil
}

type evpnRT5Path struct {
	prefix    netip.Prefix
	vni       vni.VNI
	vtepIP    netip.Addr
	rtmac     net.HardwareAddr
	rts       []string
	sourceASN uint32
}

var (
	errMissingMPReachNLRIAttr    = errors.New("missing MP_REACH_NLRI attribute")
	errMissingExtCommAttr        = errors.New("missing EXTENDED_COMMINITY attribute")
	errUnsupportedEVPNRouteType  = errors.New("unsupported EVPN route type")
	errUnsupportedESI            = errors.New("unsupported ESI value")
	errUnsupportedETag           = errors.New("unsupported ETag value")
	errUnsupportedGatewayIP      = errors.New("unsupported GatewayIP value")
	errMissingRouteTargetExtComm = errors.New("missing route-target extended-community")
	errMissingRoutersMACExtComm  = errors.New("missing router's MAC extended-community")
	errMissingEncapExtComm       = errors.New("missing encap extended-community")
	errUnsupportedEncapType      = errors.New("unsupported tunnel type")
)

func (r *importEVPNRouteReconciler) parseRoutes(routes []*types.Route) ([]*evpnRT5Path, error) {
	paths := []*evpnRT5Path{}

	for _, route := range routes {
		for _, path := range route.Paths {
			if !path.Best {
				// Ignore non-best paths
				continue
			}

			path, err := r.parsePath(path)
			if err != nil {
				// Generally, we cannot recover from parse
				// errors by retrying. So, we just record the
				// error and skip the path. It might be helpful
				// to provide metrics with error types as a
				// label helps users to identify the
				// interpoerability issues.
				r.logger.Warn("skipping path due to parse error", logfields.Error, err)
				continue
			}

			// There's only one best path. GoBGP's RIB doesn't have
			// a concept of ECMP as of today. It does support ECMP
			// with Zebra, but what they do is lazily calculate
			// ECMP paths when they notify the best path watchers
			// (that watche best paths with Watch API) and they
			// don't keep that information in the RIB. We're not
			// using Watch API, so we cannot see ECMP.
			//
			// https://github.com/osrg/gobgp/blob/f733438a965b33813b23200ea10adfa1939f5a36/pkg/server/server.go#L1392-L1395
			//
			// Also, our dataplane cannot handle it, so we anyways
			// should break here. Once we migrate to the
			// GoBGP-Watcher-based implementation and add support
			// in the datapath, we can get rid of this problem.
			paths = append(paths, path)
			break
		}
	}

	return paths, nil
}

func (r *importEVPNRouteReconciler) parseMPReachNLRI(p *bgp.PathAttributeMpReachNLRI) (netip.Prefix, vni.VNI, netip.Addr, error) {
	// We should have filtered this out with GoBGP's API call. If we see
	// any non-l2vpn/evpn paths at this point, it's a bug.
	if p.AFI != bgp.AFI_L2VPN {
		return netip.Prefix{}, vni.VNI{}, netip.Addr{}, errUnexpectedAFI
	}
	if p.SAFI != bgp.SAFI_EVPN {
		return netip.Prefix{}, vni.VNI{}, netip.Addr{}, errUnexpectedSAFI
	}

	// FIXME: Skip self-originated routes. We determine this by checking if
	// the NextHop in the MP-Reach-NLRI attribute is zero address. This is
	// not a proper way to do this. This depends on the fact that our
	// reconciler set the NextHop to zero address when it creates the
	// route. We should fix this by exposing route origin information of
	// GoBGP Path to our agent Path struct.
	if p.Nexthop.Equal(net.IPv4zero) || p.Nexthop.Equal(net.IPv6zero) {
		return netip.Prefix{}, vni.VNI{}, netip.Addr{}, errSelfOriginatedRoute
	}

	// GoBGP creates one Path per NLRI when it stores routes to the RIB,
	// even if the MP-Reach-NLRI attribute contains multiple NLRIs. So, we
	// should have only one NLRI. Here we do sanity check and skip the path
	// if there's zero or more than one NLRI.
	//
	// https://github.com/osrg/gobgp/blob/f733438a965b33813b23200ea10adfa1939f5a36/internal/pkg/table/table_manager.go#L93-L107
	if len(p.Value) != 1 {
		return netip.Prefix{}, vni.VNI{}, netip.Addr{}, errUnexpectedNumberOfNLRI
	}

	// It is safe to deref Value[0] here because we already checked the
	// length of mpReachNLRIAttr.Value above.
	nlri, ok := p.Value[0].(*bgp.EVPNNLRI)
	if !ok {
		// AFI/SAFI and type is mismatched. This is maybe a GoBGP's bug.
		return netip.Prefix{}, vni.VNI{}, netip.Addr{}, errMalformedPath
	}

	// We only support importing RT-5 for the moment
	rt5, ok := nlri.RouteTypeData.(*bgp.EVPNIPPrefixRoute)
	if !ok {
		// Unsupported EVPN route type
		return netip.Prefix{}, vni.VNI{}, netip.Addr{}, errUnsupportedEVPNRouteType
	}

	if rt5.ESI.Type != bgp.ESI_ARBITRARY {
		// We don't support non-zero ESI
		return netip.Prefix{}, vni.VNI{}, netip.Addr{}, errUnsupportedESI
	}

	if rt5.ETag != 0 {
		// We don't support non-zero ETag
		return netip.Prefix{}, vni.VNI{}, netip.Addr{}, errUnsupportedETag
	}

	addr, ok := netipx.FromStdIP(rt5.IPPrefix)
	if !ok {
		// Failed to convert net.IP => netip.Addr, maybe GoBGP's bug
		return netip.Prefix{}, vni.VNI{}, netip.Addr{}, errMalformedPath
	}

	if (addr.Is4() && !rt5.GWIPAddress.To4().IsUnspecified()) || (addr.Is6() && !rt5.GWIPAddress.To16().IsUnspecified()) {
		// We don't support non-zero gateway IP address
		return netip.Prefix{}, vni.VNI{}, netip.Addr{}, errUnsupportedGatewayIP
	}

	vtepIP, ok := netipx.FromStdIP(p.Nexthop)
	if !ok {
		// Failed to convert net.IP => netip.Addr, maybe GoBGP's bug
		return netip.Prefix{}, vni.VNI{}, netip.Addr{}, errMalformedPath
	}

	v, err := vni.FromUint32(rt5.Label)
	if err != nil {
		// Failed to convert uint32 to VNI, maybe the original route is malformed
		return netip.Prefix{}, vni.VNI{}, netip.Addr{}, errMalformedPath
	}

	return netip.PrefixFrom(addr, int(rt5.IPPrefixLength)), v, vtepIP, nil
}

func (r *importEVPNRouteReconciler) parseExtendedCommunity(p *bgp.PathAttributeExtendedCommunities) ([]string, net.HardwareAddr, error) {
	var (
		rts    []string
		rtmac  net.HardwareAddr
		tunnel bgp.TunnelType
	)

	for _, val := range p.Value {
		switch v := val.(type) {
		case *bgp.FourOctetAsSpecificExtended:
			if v.SubType == bgp.EC_SUBTYPE_ROUTE_TARGET {
				rts = append(rts, fmt.Sprintf("%d:%d", v.AS, v.LocalAdmin))
			}
		case *bgp.TwoOctetAsSpecificExtended:
			if v.SubType == bgp.EC_SUBTYPE_ROUTE_TARGET {
				rts = append(rts, fmt.Sprintf("%d:%d", v.AS, v.LocalAdmin))
			}
		case *bgp.RouterMacExtended:
			// RFC9135 Section 8.1
			// The advertising PE SHALL only attach a single EVPN
			// Router's MAC Extended Community to a route. In case
			// the receiving PE receives more than one EVPN
			// Router's MAC Extended Community with a route, it
			// SHALL process the first one in the list and not
			// store and propagate the others.
			if len(rtmac) != 0 {
				continue
			}
			rtmac = v.Mac
		case *bgp.EncapExtended:
			// There's no particular specification about multiple
			// Encap Extended Communities. We just take the first
			// one if there's multiple.
			if tunnel != 0 {
				continue
			}
			tunnel = v.TunnelType
		}
	}

	if len(rts) == 0 {
		return nil, nil, errMissingRouteTargetExtComm
	}

	if len(rtmac) == 0 {
		return nil, nil, errMissingRoutersMACExtComm
	}

	if tunnel == 0 {
		return nil, nil, errMissingEncapExtComm
	}

	if tunnel != bgp.TUNNEL_TYPE_VXLAN {
		return nil, nil, errUnsupportedEncapType
	}

	return rts, rtmac, nil
}

func (r *importEVPNRouteReconciler) parsePath(path *types.Path) (*evpnRT5Path, error) {
	var (
		mpReachNLRIAttr    *bgp.PathAttributeMpReachNLRI
		extCommunitiesAttr *bgp.PathAttributeExtendedCommunities
	)

	for _, attr := range path.PathAttributes {
		switch v := attr.(type) {
		case *bgp.PathAttributeMpReachNLRI:
			mpReachNLRIAttr = v
		case *bgp.PathAttributeExtendedCommunities:
			extCommunitiesAttr = v
		}
	}

	if mpReachNLRIAttr == nil {
		return nil, errMissingMPReachNLRIAttr
	}

	if extCommunitiesAttr == nil {
		return nil, errMissingExtCommAttr
	}

	prefix, vni, vtepIP, err := r.parseMPReachNLRI(mpReachNLRIAttr)
	if err != nil {
		return nil, err
	}

	rts, rtmac, err := r.parseExtendedCommunity(extCommunitiesAttr)
	if err != nil {
		return nil, err
	}

	return &evpnRT5Path{
		prefix:    prefix,
		vni:       vni,
		vtepIP:    vtepIP,
		rtmac:     rtmac,
		rts:       rts,
		sourceASN: path.SourceASN,
	}, nil
}
