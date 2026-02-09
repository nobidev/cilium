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
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var SubnetsCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite Subnet table.
		tables.NewSubnetTable,

		// Provides the reconciler handling private network subnets.
		newSubnets,
	),

	cell.Provide(
		// Provides the ReadOnly Subnets table.
		statedb.RWTable[tables.Subnet].ToTable,
	),

	cell.Invoke(
		// Registers the reconciler
		(*Subnets).registerReconciler,
	),
)

type Subnets struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	db       *statedb.DB
	networks statedb.Table[tables.PrivateNetwork]
	tbl      statedb.RWTable[tables.Subnet]
}

func newSubnets(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	DB       *statedb.DB
	Networks statedb.Table[tables.PrivateNetwork]
	Table    statedb.RWTable[tables.Subnet]
}) *Subnets {
	return &Subnets{
		log: in.Log,
		jg:  in.JobGroup,

		cfg: in.Config,

		db:       in.DB,
		networks: in.Networks,
		tbl:      in.Table,
	}
}

func (r *Subnets) registerReconciler() {
	if !r.cfg.Enabled {
		return
	}

	wtx := r.db.WriteTxn(r.tbl)
	initialized := r.tbl.RegisterInitializer(wtx, "subnets-initialized")
	wtx.Commit()

	// This job watches the upstream private networks table and populates the subnet table from that
	r.jg.Add(job.OneShot("populate-subnets-table", func(ctx context.Context, _ cell.Health) error {
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
					if err := r.deleteSubnets(txn, change.Object.Name); err != nil {
						txn.Abort()
						return err
					}
				} else {
					if err := r.upsertSubnets(txn, change.Object); err != nil {
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

// extractSubnets gets all subnets from a private network, but will drop any conflicting subnets.
// It will keep the first occurrence in the list if there is a conflict.
func (r *Subnets) extractSubnets(privNet tables.PrivateNetwork) map[tables.SubnetName]tables.Subnet {
	subnets := make(map[tables.SubnetName]tables.Subnet, len(privNet.Subnets))

	hasConflicts := func(subnet tables.Subnet) bool {
		if _, ok := subnets[subnet.Name]; ok {
			// This should never happen, as the subnet name is unique in the CRD
			r.log.Warn("Duplicate subnet in private network definition - inconsistent state",
				logfields.Network, privNet.Name,
				logfields.PrivateNetworkSubnet, subnet.Name,
				logfields.CIDRs, []netip.Prefix{subnet.CIDRv4, subnet.CIDRv6},
			)
			return true
		}
		for _, inserted := range subnets {
			if subnet.CIDRv4.Overlaps(inserted.CIDRv4) || subnet.CIDRv6.Overlaps(inserted.CIDRv6) {
				r.log.Warn("Duplicate subnet CIDRs in private network definition - dropping subnet",
					logfields.Network, privNet.Name,
					logfields.PrivateNetworkSubnet, subnet.Name,
					logfields.CIDR, []netip.Prefix{subnet.CIDRv4, subnet.CIDRv6},
					logfields.ConflictingPrivateNetworkSubnet, inserted.Name,
					logfields.ConflictingCIDRs, []netip.Prefix{inserted.CIDRv4, inserted.CIDRv6},
				)
				return true
			}
		}
		return false
	}

	for _, subnet := range privNet.Subnets {
		entry := tables.Subnet{
			Network:       privNet.Name,
			NetworkID:     privNet.ID,
			Name:          subnet.Name,
			CIDRv4:        subnet.CIDRv4,
			CIDRv6:        subnet.CIDRv6,
			EgressIfIndex: privNet.Interface.Index,
			EgressIfName:  privNet.Interface.Name,
		}
		if hasConflicts(entry) {
			continue
		}
		subnets[entry.Name] = entry
	}

	return subnets
}

// upsertSubnets extracts the desired subnets from the private network, removes all
// subnets no longer in the desired set, and then upserts all missing desired subnets.
func (r *Subnets) upsertSubnets(txn statedb.WriteTxn, privNet tables.PrivateNetwork) error {
	desiredSubnets := r.extractSubnets(privNet)
	// iterate over the existing subnets in the table to determine which ones to remove
	for existing := range r.tbl.Prefix(txn, tables.SubnetsByNetwork(privNet.Name)) {
		name := existing.Name
		desired, ok := desiredSubnets[name]
		if !ok {
			// if the subnet is not in the desired set, remove it
			_, _, err := r.tbl.Delete(txn, existing)
			if err != nil {
				return err
			}
		} else if desired.Equals(existing) {
			// if the desired subnet exactly matches the existing one,
			// we do not need to re-insert it
			delete(desiredSubnets, name)
		}
	}

	// upsert remaining desired subnets
	for _, subnet := range desiredSubnets {
		_, _, err := r.tbl.Insert(txn, subnet)
		if err != nil {
			return err
		}
	}

	return nil
}

// deleteNetworkRoutes removes all subnets belonging to a network
func (r *Subnets) deleteSubnets(txn statedb.WriteTxn, privNetName tables.NetworkName) error {
	for entry := range r.tbl.Prefix(txn, tables.SubnetsByNetwork(privNetName)) {
		_, _, err := r.tbl.Delete(txn, entry)
		if err != nil {
			return err
		}
	}
	return nil
}
