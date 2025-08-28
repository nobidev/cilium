//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package reconcilers

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var RoutesCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite Routes table.
		tables.NewRouteTable,

		// Provides the reconciler handling private network routes.
		newRoutes,
	),

	cell.Provide(
		// Provides the ReadOnly Routes table.
		statedb.RWTable[tables.Route].ToTable,
	),

	cell.Invoke(
		// Registers the reconciler
		(*Routes).registerReconciler,
	),
)

// Routes is a reconciler which watches the private network table and populates the routes table from that
type Routes struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	db       *statedb.DB
	networks statedb.Table[tables.PrivateNetwork]
	tbl      statedb.RWTable[tables.Route]
}

func newRoutes(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	DB       *statedb.DB
	Networks statedb.Table[tables.PrivateNetwork]
	Table    statedb.RWTable[tables.Route]
}) (*Routes, error) {
	reconciler := &Routes{
		log: in.Log,
		jg:  in.JobGroup,

		cfg: in.Config,

		db:       in.DB,
		networks: in.Networks,
		tbl:      in.Table,
	}

	return reconciler, nil
}

func (r *Routes) registerReconciler() {
	if !r.cfg.Enabled {
		return
	}

	wtx := r.db.WriteTxn(r.tbl)
	initialized := r.tbl.RegisterInitializer(wtx, "routes-initialized")
	wtx.Commit()

	// This job watches the upstream private networks table and populates the routes table from that
	r.jg.Add(job.OneShot("populate-routes-table", func(ctx context.Context, _ cell.Health) error {
		var initDone bool

		txn := r.db.WriteTxn(r.networks)
		changeIter, _ := r.networks.Changes(txn)
		txn.Commit()

		for {
			var initWatch <-chan struct{}
			txn := r.db.WriteTxn(r.tbl)
			changes, watch := changeIter.Next(txn)

			for change := range changes {
				r.log.Debug("Processing table event",
					logfields.Table, r.networks.Name(),
					logfields.Event, change,
				)

				if change.Deleted {
					if err := r.deleteNetworkRoutes(txn, change.Object.Name); err != nil {
						txn.Abort()
						return err
					}
				} else {
					if err := r.upsertNetworkRoutes(txn, change.Object); err != nil {
						txn.Abort()
						return err
					}
				}
			}

			// In order to be able to propagate initialization, we need to check if the upstream
			// tables have already been initialized
			if !initDone {
				init, nw := r.networks.Initialized(txn)

				switch {
				case !init:
					initWatch = nw
				default:
					initDone = true
					initialized(txn)
				}
			}

			txn.Commit()

			// Wait until there's new changes to consume
			select {
			case <-ctx.Done():
				return nil
			case <-watch:
			case <-initWatch:
			}
		}
	}))
}

// extractRoutes extracts the routes from the private network and stores it in a map, indexed
// by the StateDB key (which contains the route destination). If it detects a key conflict,
// it logs a warning and ignores the conflicting entry. Subnet entries take precedence over
// route entries.
func (r *Routes) extractRoutes(privNet tables.PrivateNetwork) map[tables.RouteKey]tables.Route {
	routes := make(map[tables.RouteKey]tables.Route, len(privNet.Subnets)+len(privNet.Routes))
	for _, subnet := range privNet.Subnets {
		entry := tables.Route{
			Network:     privNet.Name,
			Destination: subnet.CIDR,
		}
		key := entry.Key()
		if _, ok := routes[key]; ok {
			r.log.Warn("Duplicate subnet in private network definition",
				logfields.Network, privNet.Name,
				logfields.CIDR, subnet.CIDR,
			)
			continue
		}
		routes[key] = entry
	}

	for _, route := range privNet.Routes {
		entry := tables.Route{
			Network:     privNet.Name,
			Destination: route.Destination,
			Gateway:     route.Gateway,
		}
		key := entry.Key()
		if _, ok := routes[key]; ok {
			r.log.Warn("Duplicate route destination in private network definition",
				logfields.Network, privNet.Name,
				logfields.CIDR, route.Destination,
			)
			continue
		}
		routes[key] = entry
	}

	return routes
}

// upsertNetworkRoutes extracts the desired routes from the private network, removes all
// routes no longer in the desired set, and then upserts all missing desired routes.
func (r *Routes) upsertNetworkRoutes(txn statedb.WriteTxn, privNet tables.PrivateNetwork) error {
	desiredRoutes := r.extractRoutes(privNet)
	// iterate over the existing routes in the table to determine which ones to remove
	for existing := range r.tbl.Prefix(txn, tables.RouteByNetwork(privNet.Name)) {
		routeKey := existing.Key()
		desired, ok := desiredRoutes[routeKey]
		if !ok {
			// if the route is not in the desired set, remove it
			_, _, err := r.tbl.Delete(txn, existing)
			if err != nil {
				return err
			}
		} else if desired == existing {
			// if the desired route exactly matches the existing one,
			// we do not need to re-insert it
			delete(desiredRoutes, routeKey)
		}
	}

	// upsert remaining desired routes
	for _, route := range desiredRoutes {
		_, _, err := r.tbl.Insert(txn, route)
		if err != nil {
			return err
		}
	}

	return nil
}

// deleteNetworkRoutes removes all routes belonging to a network
func (r *Routes) deleteNetworkRoutes(txn statedb.WriteTxn, privNetName tables.NetworkName) error {
	for entry := range r.tbl.Prefix(txn, tables.RouteByNetwork(privNetName)) {
		_, _, err := r.tbl.Delete(txn, entry)
		if err != nil {
			return err
		}
	}
	return nil
}
