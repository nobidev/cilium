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

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"go4.org/netipx"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// AdminDistance must be farer than default AD (100) to avoid
	// overriding Cilium-managed routes. iBGP routes must have higher AD
	// than eBGP routes (this aligns with the conventional routers).
	AdminDistanceIBGP = routeReconciler.AdminDistance(200)
	AdminDistanceEBGP = routeReconciler.AdminDistance(150)
)

type importRouteReconcilerOut struct {
	cell.Out

	Reconciler reconciler.StateReconciler `group:"bgp-state-reconciler"`
}

type importRouteReconcilerIn struct {
	cell.In

	Logger              *slog.Logger
	Config              config.Config
	EnterpriseConfig    Config
	Upgrader            paramUpgrader
	DB                  *statedb.DB
	DesiredRouteManager *routeReconciler.DesiredRouteManager
	DesiredRouteTable   statedb.Table[*routeReconciler.DesiredRoute]
	DeviceTable         statedb.Table[*tables.Device]
}

type importRouteReconciler struct {
	logger            *slog.Logger
	upgrader          paramUpgrader
	drm               *routeReconciler.DesiredRouteManager
	db                *statedb.DB
	desiredRoutetable statedb.Table[*routeReconciler.DesiredRoute]
	deviceTable       statedb.Table[*tables.Device]
}

func newImportRouteReconciler(in importRouteReconcilerIn) importRouteReconcilerOut {
	if !in.Config.Enabled || !in.EnterpriseConfig.RouteImportEnabled {
		return importRouteReconcilerOut{}
	}
	return importRouteReconcilerOut{
		Reconciler: &importRouteReconciler{
			logger:            in.Logger,
			upgrader:          in.Upgrader,
			drm:               in.DesiredRouteManager,
			db:                in.DB,
			desiredRoutetable: in.DesiredRouteTable,
			deviceTable:       in.DeviceTable,
		},
	}
}

func (r *importRouteReconciler) Name() string {
	return ImportRouteReconcilerName
}

func (r *importRouteReconciler) Priority() int {
	return ImportRouteReconcilerPriority
}

func (r *importRouteReconciler) Reconcile(ctx context.Context, _p reconciler.StateReconcileParams) error {
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

	// Clear all desired route entries inserted by the deleted instance
	if p.DeletedInstance != "" {
		owner, err := r.drm.GetOwner(r.ownerName(p.DeletedInstance))
		if errors.Is(err, routeReconciler.ErrOwnerDoesNotExist) {
			return nil
		}
		return r.drm.RemoveOwner(owner)
	}

	owner, err := r.drm.GetOrRegisterOwner(r.ownerName(p.UpdatedInstance.Name))
	if err != nil {
		return err
	}

	desiredPaths, err := r.desiredPaths(ctx, p.UpdatedInstance.Router)
	if err != nil {
		return err
	}

	rtxn := r.db.ReadTxn()

	currentPaths, err := r.currentPaths(ctx, rtxn, owner)
	if err != nil {
		return err
	}

	toUpsert, toDelete := r.calculateDiff(desiredPaths, currentPaths)

	return r.reconcileDesiredRoutes(ctx, rtxn, owner, toUpsert, toDelete)
}

type path struct {
	prefix  netip.Prefix
	nexthop netip.Addr
	isIBGP  bool
}

func (r *importRouteReconciler) desiredPaths(ctx context.Context, router types.EnterpriseRouter) (map[netip.Prefix]*path, error) {
	global, err := router.GetBGP(ctx)
	if err != nil {
		return nil, err
	}

	resv4, err := router.GetRoutesExtended(ctx, &types.GetRoutesExtendedRequest{
		GetRoutesRequest: ossTypes.GetRoutesRequest{
			TableType: ossTypes.TableTypeLocRIB,
			Family: ossTypes.Family{
				Afi:  ossTypes.AfiIPv4,
				Safi: ossTypes.SafiUnicast,
			},
		},
	})
	if err != nil {
		r.logger.Error("Error getting IPv4 routes", logfields.Error, err)
		return nil, err
	}

	v4Paths, err := r.parsePaths(resv4.Routes, true, global.Global.ASN)
	if err != nil {
		// Just generate a log for the parse errors.
		// TODO: Expose metrics per error type.
		r.logger.Debug("Error parsing IPv4 paths", logfields.Error, err)
	}

	resv6, err := router.GetRoutesExtended(ctx, &types.GetRoutesExtendedRequest{
		GetRoutesRequest: ossTypes.GetRoutesRequest{
			TableType: ossTypes.TableTypeLocRIB,
			Family: ossTypes.Family{
				Afi:  ossTypes.AfiIPv6,
				Safi: ossTypes.SafiUnicast,
			},
		},
	})
	if err != nil {
		r.logger.Error("Error getting IPv6 routes", logfields.Error, err)
		return nil, err
	}

	v6Paths, err := r.parsePaths(resv6.Routes, false, global.Global.ASN)
	if err != nil {
		// Just generate a log for the parse errors.
		// TODO: Expose metrics per error type.
		r.logger.Debug("Error parsing IPv6 paths", logfields.Error, err)
	}

	maps.Copy(v4Paths, v6Paths)

	return v4Paths, nil
}

func (r *importRouteReconciler) parsePaths(routes []*types.ExtendedRoute, isV4 bool, selfASN uint32) (map[netip.Prefix]*path, error) {
	var errs error

	paths := map[netip.Prefix]*path{}

	for _, route := range routes {
		bestPaths := []*types.ExtendedPath{}
		for _, p := range route.Paths {
			if !p.Best {
				continue
			}
			bestPaths = append(bestPaths, p)
		}

		if len(bestPaths) == 0 || len(bestPaths) > 1 {
			// We only handle single best path routes for now. ECMP
			// is not supported.
			continue
		}

		var (
			parsed *path
			err    error
		)
		if isV4 {
			parsed, err = r.parseV4Path(bestPaths[0], selfASN)
			if err != nil {
				errs = errors.Join(errs, err)
				continue
			}
		} else {
			parsed, err = r.parseV6Path(bestPaths[0], selfASN)
			if err != nil {
				errs = errors.Join(errs, err)
				continue
			}
		}

		if parsed.nexthop.IsUnspecified() {
			// Skip self-originated routes
			continue
		}

		paths[parsed.prefix] = parsed
	}

	return paths, errs
}

func (r *importRouteReconciler) parseV4Path(p *types.ExtendedPath, selfASN uint32) (*path, error) {
	// For IPv4, we have two possible nexthopAttr encodings. One is the legacy
	// IPv4 NEXT_HOP attribute, and the other is the MP_REACH_NLRI
	// attribute. We need to handle both cases.
	var (
		nexthopAttr     *bgp.PathAttributeNextHop
		mpReachNLRIAttr *bgp.PathAttributeMpReachNLRI
	)

	for _, attr := range p.PathAttributes {
		switch a := attr.(type) {
		case *bgp.PathAttributeNextHop:
			nexthopAttr = a
		case *bgp.PathAttributeMpReachNLRI:
			mpReachNLRIAttr = a
		}
	}

	if nexthopAttr == nil && mpReachNLRIAttr == nil {
		return nil, errMalformedPath
	}

	nlri, ok := p.NLRI.(*bgp.IPAddrPrefix)
	if !ok {
		return nil, errMalformedNLRI
	}

	nlriAddr, ok := netipx.FromStdIP(nlri.Prefix)
	if !ok {
		return nil, errMalformedNLRI
	}

	prefix := netip.PrefixFrom(nlriAddr, int(nlri.Length))

	var (
		err     error
		nexthop netip.Addr
	)
	if mpReachNLRIAttr != nil {
		// Whenever MP_REACH_NLRI is present, it takes precedence over
		// the legacy NEXT_HOP attribute.
		nexthop, err = r.parseMPReachNLRINexthop(mpReachNLRIAttr, p.NeighborAddr)
		if err != nil {
			return nil, err
		}
	} else {
		nexthop, ok = netipx.FromStdIP(nexthopAttr.Value)
		if !ok {
			return nil, errMalformedNexthop
		}
		if !nexthop.Is4() {
			return nil, errUnsupportedNexthop
		}
	}

	return &path{
		prefix:  prefix,
		nexthop: nexthop,
		isIBGP:  p.SourceASN == selfASN,
	}, nil
}

func (r *importRouteReconciler) parseV6Path(p *types.ExtendedPath, selfASN uint32) (*path, error) {
	// For IPv6, we only expect the MP_REACH_NLRI attribute to be present.
	var mpReachNLRIAttr *bgp.PathAttributeMpReachNLRI

	for _, attr := range p.PathAttributes {
		switch a := attr.(type) {
		case *bgp.PathAttributeMpReachNLRI:
			mpReachNLRIAttr = a
		}
	}

	if mpReachNLRIAttr == nil {
		return nil, errMalformedPath
	}

	nlri, ok := p.NLRI.(*bgp.IPv6AddrPrefix)
	if !ok {
		return nil, errMalformedNLRI
	}

	nlriAddr, ok := netipx.FromStdIP(nlri.Prefix)
	if !ok {
		return nil, errMalformedNLRI
	}

	nexthop, err := r.parseMPReachNLRINexthop(mpReachNLRIAttr, p.NeighborAddr)
	if err != nil {
		return nil, err
	}

	// Non-IPv6 nexthop in IPv6 route is not supported.
	if !nexthop.Is6() {
		return nil, errUnsupportedNexthop
	}

	return &path{
		prefix:  netip.PrefixFrom(nlriAddr, int(nlri.Length)),
		nexthop: nexthop,
		isIBGP:  p.SourceASN == selfASN,
	}, nil
}

func (r *importRouteReconciler) parseMPReachNLRINexthop(mpReachNLRIAttr *bgp.PathAttributeMpReachNLRI, neighborAddr netip.Addr) (netip.Addr, error) {
	var (
		linkLocalNexthop netip.Addr
		globalNexthop    netip.Addr
	)

	if len(mpReachNLRIAttr.LinkLocalNexthop) > 0 {
		nh, ok := netipx.FromStdIP(mpReachNLRIAttr.LinkLocalNexthop)
		if !ok {
			return netip.Addr{}, errMalformedNexthop
		}
		if !nh.IsLinkLocalUnicast() {
			return netip.Addr{}, errMalformedNexthop
		}
		linkLocalNexthop = nh
	}

	if len(mpReachNLRIAttr.Nexthop) > 0 {
		nh, ok := netipx.FromStdIP(mpReachNLRIAttr.Nexthop)
		if !ok {
			return netip.Addr{}, errMalformedNexthop
		}
		globalNexthop = nh // This can be link-local (possible with BGP Unnumbered) or global
	}

	switch {
	case linkLocalNexthop.IsValid() && linkLocalNexthop.Is6() && neighborAddr.Zone() != "":
		// IPv6 link-local nexthop present and we can derive the
		// interface from the neighbor address zone. Use it. This
		// covers BGP Unnumbered ::/LL and LL/LL encodings.
		return linkLocalNexthop.WithZone(neighborAddr.Zone()), nil
	case globalNexthop.IsValid() && globalNexthop.Is6() && globalNexthop.IsLinkLocalUnicast() && neighborAddr.Zone() != "":
		// IPv6 global nexthop is link-local address and we can derive
		// the interface from the neighbor address zone. Use it. This
		// covers BGP Unnumbered LL encoding.
		return globalNexthop.WithZone(neighborAddr.Zone()), nil
	case globalNexthop.IsValid() && !globalNexthop.IsUnspecified() && !globalNexthop.IsLinkLocalUnicast():
		// The true global nexthop case.
		return globalNexthop, nil
	default:
		// We cannot support any other cases.
		return netip.Addr{}, errUnsupportedNexthop
	}
}

func (r *importRouteReconciler) currentPaths(ctx context.Context, rtxn statedb.ReadTxn, owner *routeReconciler.RouteOwner) (map[netip.Prefix]*path, error) {
	paths := map[netip.Prefix]*path{}

	// List all routes owned by this BGP instance
	for rt := range r.desiredRoutetable.Prefix(rtxn, routeReconciler.DesiredRouteIndex.Query(routeReconciler.DesiredRouteKey{Owner: owner})) {
		if rt.Table != routeReconciler.TableMain {
			continue
		}
		p, err := r.toPath(owner, rt)
		if err != nil {
			continue
		}
		paths[rt.Prefix] = p
	}

	return paths, nil
}

func (r *importRouteReconciler) calculateDiff(desired, current map[netip.Prefix]*path) ([]*path, []*path) {
	var (
		toUpsert []*path
		toDelete []*path
	)

	for prefix, d := range desired {
		c, exists := current[prefix]
		if !exists || d != c {
			toUpsert = append(toUpsert, d)
		}
	}

	for prefix, c := range current {
		_, exists := desired[prefix]
		if !exists {
			toDelete = append(toDelete, c)
		}
	}

	return toUpsert, toDelete
}

func (r *importRouteReconciler) toTableRoute(rtxn statedb.ReadTxn, owner *routeReconciler.RouteOwner, p *path) (routeReconciler.DesiredRoute, error) {
	ad := AdminDistanceEBGP
	if p.isIBGP {
		ad = AdminDistanceIBGP
	}

	var device *tables.Device
	if p.nexthop.Zone() != "" {
		dev, _, found := r.deviceTable.Get(rtxn, tables.DeviceNameIndex.Query(p.nexthop.Zone()))
		if !found {
			return routeReconciler.DesiredRoute{}, fmt.Errorf("device %q not found for nexthop %q", p.nexthop.Zone(), p.nexthop)
		}
		device = dev
	}

	return routeReconciler.DesiredRoute{
		Owner:         owner,
		Prefix:        p.prefix,
		Nexthop:       p.nexthop,
		Device:        device,
		Table:         routeReconciler.TableMain,
		AdminDistance: ad,
		Type:          routeReconciler.RTN_UNICAST,
	}, nil
}

// toPath converts a DesiredRoute to an intermediate path representation. This
// must be the inverse of toTableRoute.
func (r *importRouteReconciler) toPath(owner *routeReconciler.RouteOwner, rt *routeReconciler.DesiredRoute) (*path, error) {
	// Sanity checks for the constant fields.
	if rt.Owner != owner {
		return nil, fmt.Errorf("owner mismatch: got %v, want %v", rt.Owner, owner)
	}
	if rt.Table != routeReconciler.TableMain {
		return nil, fmt.Errorf("table is not main: %d", rt.Table)
	}
	if rt.AdminDistance != AdminDistanceIBGP && rt.AdminDistance != AdminDistanceEBGP {
		return nil, fmt.Errorf("AD is not IBGP or EBGP: %d", rt.AdminDistance)
	}
	if rt.Type != routeReconciler.RTN_UNICAST {
		return nil, fmt.Errorf("route type is not unicast: %d", rt.Type)
	}

	nexthop := rt.Nexthop
	if nexthop.Is6() && nexthop.IsLinkLocalUnicast() && rt.Device != nil {
		// If the nexthop is IPv6 link-local address and a
		// device associated, add the zone to the nexthop.
		nexthop = rt.Nexthop.WithZone(rt.Device.Name)
	}

	return &path{
		prefix:  rt.Prefix,
		nexthop: nexthop,
		isIBGP:  rt.AdminDistance == AdminDistanceIBGP,
	}, nil
}

func (r *importRouteReconciler) reconcileDesiredRoutes(ctx context.Context, rtxn statedb.ReadTxn, owner *routeReconciler.RouteOwner, toUpsert, toDelete []*path) error {
	var errs error
	for _, p := range toUpsert {
		route, err := r.toTableRoute(rtxn, owner, p)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		if err := r.drm.UpsertRoute(route); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	for _, p := range toDelete {
		route, err := r.toTableRoute(rtxn, owner, p)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		if err := r.drm.DeleteRoute(route); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	return errs
}

func (r *importRouteReconciler) ownerName(instanceName string) string {
	return "bgp-" + instanceName
}
