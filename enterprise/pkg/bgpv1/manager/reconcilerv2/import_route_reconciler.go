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
	"log/slog"
	"maps"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"go4.org/netipx"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/types"
	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
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
}

type importRouteReconciler struct {
	logger   *slog.Logger
	upgrader paramUpgrader
	drm      *routeReconciler.DesiredRouteManager
	db       *statedb.DB
	tbl      statedb.Table[*routeReconciler.DesiredRoute]
}

func newImportRouteReconciler(in importRouteReconcilerIn) importRouteReconcilerOut {
	if !in.Config.Enabled || !in.EnterpriseConfig.RouteImportEnabled {
		return importRouteReconcilerOut{}
	}
	return importRouteReconcilerOut{
		Reconciler: &importRouteReconciler{
			logger:   in.Logger,
			upgrader: in.Upgrader,
			drm:      in.DesiredRouteManager,
			db:       in.DB,
			tbl:      in.DesiredRouteTable,
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

	currentPaths, err := r.currentPaths(ctx, owner)
	if err != nil {
		return err
	}

	toUpsert, toDelete := r.calculateDiff(desiredPaths, currentPaths)

	return r.reconcileDesiredRoutes(ctx, owner, toUpsert, toDelete)
}

type path struct {
	prefix  netip.Prefix
	nexthop netip.Addr
	isIBGP  bool
}

func (r *importRouteReconciler) desiredPaths(ctx context.Context, router types.Router) (map[netip.Prefix]*path, error) {
	global, err := router.GetBGP(ctx)
	if err != nil {
		return nil, err
	}

	resv4, err := router.GetRoutes(ctx, &types.GetRoutesRequest{
		TableType: types.TableTypeLocRIB,
		Family: types.Family{
			Afi:  types.AfiIPv4,
			Safi: types.SafiUnicast,
		},
	})
	if err != nil {
		return nil, err
	}

	v4Paths, err := r.parsePaths(resv4.Routes, true, global.Global.ASN)
	if err != nil {
		// Just generate a log for the parse errors.
		// TODO: Expose metrics per error type.
		r.logger.Debug("Error parsing IPv4 paths", logfields.Error, err)
	}

	resv6, err := router.GetRoutes(ctx, &types.GetRoutesRequest{
		TableType: types.TableTypeLocRIB,
		Family: types.Family{
			Afi:  types.AfiIPv6,
			Safi: types.SafiUnicast,
		},
	})
	if err != nil {
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

func (r *importRouteReconciler) parsePaths(routes []*types.Route, isV4 bool, selfASN uint32) (map[netip.Prefix]*path, error) {
	var errs error

	paths := map[netip.Prefix]*path{}

	for _, route := range routes {
		bestPaths := []*types.Path{}
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

func (r *importRouteReconciler) parseV4Path(p *types.Path, selfASN uint32) (*path, error) {
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

	var nexthop netip.Addr
	if mpReachNLRIAttr != nil {
		// Whenever MP_REACH_NLRI is present, it takes precedence over
		// the legacy NEXT_HOP attribute.
		nexthop, ok = netipx.FromStdIP(mpReachNLRIAttr.Nexthop)
		if !ok {
			return nil, errMalformedNexthop
		}
	} else {
		nexthop, ok = netipx.FromStdIP(nexthopAttr.Value)
		if !ok {
			return nil, errMalformedNexthop
		}
	}

	if !nexthop.Is4() {
		return nil, errUnsupportedNexthop
	}

	return &path{
		prefix:  prefix,
		nexthop: nexthop,
		isIBGP:  p.SourceASN == selfASN,
	}, nil
}

func (r *importRouteReconciler) parseV6Path(p *types.Path, selfASN uint32) (*path, error) {
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

	prefix := netip.PrefixFrom(nlriAddr, int(nlri.Length))

	var nexthop netip.Addr
	switch {
	case len(mpReachNLRIAttr.LinkLocalNexthop) > 0:
		// Whenever we have a link-local nexthop, we will use that one.
		nexthop, ok = netipx.FromStdIP(mpReachNLRIAttr.LinkLocalNexthop)
		if !ok {
			return nil, errMalformedNexthop
		}
		// Encoding global address to link-local nexthop field is invalid
		if !nexthop.IsLinkLocalUnicast() {
			return nil, errMalformedNexthop
		}
	case len(mpReachNLRIAttr.Nexthop) > 0:
		// Otherwise, we use the global nexthop.
		nexthop, ok = netipx.FromStdIP(mpReachNLRIAttr.Nexthop)
		if !ok {
			return nil, errMalformedNexthop
		}
		// Encoding link-local address to global nexthop field is
		// unfortunately possible for BGP Unnumbered case.
	default:
		// No nexthop present. Malformed.
		return nil, errMalformedNexthop
	}

	if !nexthop.Is6() {
		return nil, errUnsupportedNexthop
	}

	return &path{
		prefix:  prefix,
		nexthop: nexthop,
		isIBGP:  p.SourceASN == selfASN,
	}, nil
}

func (r *importRouteReconciler) currentPaths(ctx context.Context, owner *routeReconciler.RouteOwner) (map[netip.Prefix]*path, error) {
	paths := map[netip.Prefix]*path{}

	rtxn := r.db.ReadTxn()

	// List all routes owned by this BGP instance
	for rt := range r.tbl.Prefix(rtxn, routeReconciler.DesiredRouteIndex.Query(routeReconciler.DesiredRouteKey{Owner: owner})) {
		if rt.Table != routeReconciler.TableMain {
			continue
		}
		paths[rt.Prefix] = &path{
			prefix:  rt.Prefix,
			nexthop: rt.Nexthop,
			isIBGP:  rt.AdminDistance == AdminDistanceIBGP,
		}
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

func (r *importRouteReconciler) toTableRoute(owner *routeReconciler.RouteOwner, p *path) routeReconciler.DesiredRoute {
	ad := AdminDistanceEBGP
	if p.isIBGP {
		ad = AdminDistanceIBGP
	}
	return routeReconciler.DesiredRoute{
		Owner:         owner,
		Prefix:        p.prefix,
		Nexthop:       p.nexthop,
		Table:         routeReconciler.TableMain,
		AdminDistance: ad,
		Type:          routeReconciler.RTN_UNICAST,
	}
}

func (r *importRouteReconciler) reconcileDesiredRoutes(ctx context.Context, owner *routeReconciler.RouteOwner, toUpsert, toDelete []*path) error {
	var errs error
	for _, p := range toUpsert {
		route := r.toTableRoute(owner, p)
		if err := r.drm.UpsertRoute(route); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	for _, p := range toDelete {
		route := r.toTableRoute(owner, p)
		if err := r.drm.DeleteRoute(route); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	return errs
}

func (r *importRouteReconciler) ownerName(instanceName string) string {
	return "bgp-" + instanceName
}
