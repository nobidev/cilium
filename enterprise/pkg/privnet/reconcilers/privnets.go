// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	dptables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/k8s"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	cs_iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
)

var PrivateNetworksCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite PrivateNetworks table.
		tables.NewPrivateNetworksTable,

		// Provides the reconciler handling private networks.
		newPrivateNetworks,
	),

	cell.Provide(
		// Provide the IDPool via hive, so that it can be overridden for testing
		// purposes, as we will want stable IDs there.
		newDefaultIDPool,

		// Provides the ReadOnly PrivateNetworks table.
		statedb.RWTable[tables.PrivateNetwork].ToTable,
	),

	cell.Invoke(
		// Registers the k8s to table reflector.
		(*PrivateNetworks).registerK8sReflector,

		// Register the reconciler reacting to device changes.
		(*PrivateNetworks).registerDeviceChangesReconciler,

		// Register the reconciler to release stale network IDs.
		(*PrivateNetworks).registerIDsReleaser,
	),
)

// PrivateNetworks is the reconciler for private networks.
type PrivateNetworks struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	db   *statedb.DB
	tbl  statedb.RWTable[tables.PrivateNetwork]
	devs statedb.Table[*dptables.Device]

	client cs_iso_v1alpha1.ClusterwidePrivateNetworkInterface
}

func newPrivateNetworks(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	DB      *statedb.DB
	Table   statedb.RWTable[tables.PrivateNetwork]
	Devices statedb.Table[*dptables.Device]

	Client client.Clientset
}) (*PrivateNetworks, error) {
	reconciler := &PrivateNetworks{
		log:  in.Log,
		jg:   in.JobGroup,
		cfg:  in.Config,
		db:   in.DB,
		tbl:  in.Table,
		devs: in.Devices,
	}

	if !in.Config.Enabled {
		return reconciler, nil
	}

	if !in.Client.IsEnabled() {
		return nil, errors.New("private networks requires Kubernetes support to be enabled")
	}

	reconciler.client = in.Client.IsovalentV1alpha1().ClusterwidePrivateNetworks()
	return reconciler, nil
}

func (pn *PrivateNetworks) registerK8sReflector(idpool *IDPool, sync promise.Promise[synced.CRDSync]) error {
	if !pn.cfg.Enabled {
		return nil
	}

	cfg := k8s.ReflectorConfig[tables.PrivateNetwork]{
		Name:          "to-table", // the full name will be "job-k8s-reflector-private-networks-to-table"
		Table:         pn.tbl,
		ListerWatcher: utils.ListerWatcherFromTyped(pn.client),
		MetricScope:   "ClusterwidePrivateNetwork",
		CRDSync:       sync,

		Transform: func(txn statedb.ReadTxn, obj any) (tables.PrivateNetwork, bool) {
			privnet, ok := obj.(*iso_v1alpha1.ClusterwidePrivateNetwork)
			if !ok {
				return tables.PrivateNetwork{}, false
			}

			// Retrieve the current ID, if already assigned.
			id := tables.NetworkIDReserved
			if curr, _, found := pn.tbl.Get(txn, tables.PrivateNetworkByName(tables.NetworkName(privnet.Name))); found {
				id = curr.ID
			}

			// Attempt to acquire a new ID, if not already assigned.
			if id == tables.NetworkIDReserved {
				var err error
				id, err = idpool.acquire()
				if err != nil {
					pn.log.Error("Failed to assign network ID to private network",
						logfields.Error, err,
						logfields.ClusterwidePrivateNetwork, privnet.Name,
					)
					return tables.PrivateNetwork{}, false
				}
			}

			var iface tables.PrivateNetworkInterface
			// Set the interface name only if we are not running in bridge mode,
			// to prevent surprises in case the same manifests get reused.
			if ifname := privnet.Spec.Interface.Name; pn.cfg.EnabledAsBridge() && ifname != "" {
				// The devices controller, which provides the devices table, has
				// a start hook that returns only after that the first initialization
				// completed. Hence, here we are guaranteed that the devices table
				// is already initialized. We configure the interface parameters
				// at this point, in addition to via the dedicated job, to ensure
				// that they are correctly populated on startup, when the table
				// is marked as initialized.
				dev, _, _ := pn.devs.Get(txn, dptables.DeviceNameIndex.Query(ifname))
				iface = pn.newInterface(ifname, dev)
			}

			inbs := pn.extractINBs(privnet)
			routes := pn.extractRoutes(privnet)
			subnets := pn.extractSubnets(privnet)

			return tables.PrivateNetwork{
				Name:      tables.NetworkName(privnet.Name),
				ID:        id,
				INBs:      inbs,
				Interface: iface,
				Routes:    routes,
				Subnets:   subnets,
			}, true
		},
	}

	return k8s.RegisterReflector(pn.jg, pn.db, cfg)
}

func (pn *PrivateNetworks) extractINBs(privnet *iso_v1alpha1.ClusterwidePrivateNetwork) tables.PrivateNetworkINBs {
	inbs := make([]netip.Addr, 0, len(privnet.Spec.INBs))
	for _, inbAddr := range privnet.Spec.INBs {
		inb, err := netip.ParseAddr(string(inbAddr.IP))
		if err != nil {
			pn.log.Error("Encountered invalid INB address in private network spec",
				logfields.IPAddr, inbAddr,
				logfields.Error, err,
				logfields.ClusterwidePrivateNetwork, privnet.Name,
			)
			continue
		}
		inbs = append(inbs, inb)
	}
	return tables.PrivateNetworkINBs{IPs: inbs}
}

func (pn *PrivateNetworks) extractRoutes(privnet *iso_v1alpha1.ClusterwidePrivateNetwork) []tables.PrivateNetworkRoute {
	routes := make([]tables.PrivateNetworkRoute, 0, len(privnet.Spec.Routes))
	for _, routeSpec := range privnet.Spec.Routes {
		dst, err := netip.ParsePrefix(string(routeSpec.Destination))
		if err != nil {
			pn.log.Error("Encountered invalid route destination in private network spec",
				logfields.CIDR, routeSpec.Destination,
				logfields.Error, err,
				logfields.ClusterwidePrivateNetwork, privnet.Name,
			)
			continue
		}

		gw, err := netip.ParseAddr(string(routeSpec.Gateway))
		if err != nil {
			pn.log.Error("Encountered invalid route gateway in private network spec",
				logfields.IPAddr, routeSpec.Gateway,
				logfields.Error, err,
				logfields.ClusterwidePrivateNetwork, privnet.Name,
			)
			continue
		}

		routes = append(routes, tables.PrivateNetworkRoute{
			Destination: dst,
			Gateway:     gw,
		})
	}
	return routes
}

func (pn *PrivateNetworks) extractSubnets(privnet *iso_v1alpha1.ClusterwidePrivateNetwork) []tables.PrivateNetworkSubnet {
	subnets := make([]tables.PrivateNetworkSubnet, 0, len(privnet.Spec.Subnets))
	for _, subnetPrefix := range privnet.Spec.Subnets {
		subnet, err := netip.ParsePrefix(string(subnetPrefix.CIDR))
		if err != nil {
			pn.log.Error("Encountered invalid subnet CIDR in private network spec",
				logfields.CIDR, subnetPrefix,
				logfields.Error, err,
				logfields.ClusterwidePrivateNetwork, privnet.Name,
			)
			continue
		}
		subnets = append(subnets, tables.PrivateNetworkSubnet{
			CIDR: subnet,
		})
	}
	return subnets
}

func (pn *PrivateNetworks) registerDeviceChangesReconciler() {
	if !pn.cfg.Enabled {
		return
	}

	pn.jg.Add(
		job.OneShot(
			"private-networks-device-changes",
			pn.reconcileDeviceChanges,
		),
	)
}

func (pn *PrivateNetworks) reconcileDeviceChanges(ctx context.Context, health cell.Health) error {
	health.OK("Starting")
	for {
		txn := pn.db.WriteTxn(pn.tbl)

		devs := make(map[string]*dptables.Device)
		devsIter, devsWatch := pn.devs.AllWatch(txn)
		for dev := range devsIter {
			devs[dev.Name] = dev
		}

		privnets := pn.tbl.All(txn)
		for privnet := range privnets {
			ifname := privnet.Interface.Name
			if ifname == "" {
				continue
			}

			iface := pn.newInterface(ifname, devs[ifname])
			if privnet.Interface != iface {
				copy := privnet
				copy.Interface = iface
				pn.tbl.Insert(txn, copy)
			}
		}

		txn.Commit()
		health.OK("Reconciliation completed")

		select {
		case <-devsWatch:
		case <-ctx.Done():
			return nil
		}
	}
}

func (pn *PrivateNetworks) registerIDsReleaser(idpool *IDPool) {
	if !pn.cfg.Enabled {
		return
	}

	pn.jg.Add(
		job.OneShot(
			"private-networks-release-ids",
			func(ctx context.Context, health cell.Health) error {
				wtx := pn.db.WriteTxn(pn.tbl)
				changeIter, _ := pn.tbl.Changes(wtx)
				wtx.Commit()

				health.OK("Primed")
				for {
					var count uint
					changes, watch := changeIter.Next(pn.db.ReadTxn())

					for change := range changes {
						if change.Deleted && change.Object.ID != tables.NetworkIDReserved {
							idpool.release(change.Object.ID)
							count++
						}
					}

					if count > 0 {
						health.OK(fmt.Sprintf("%d IDs released", count))
					}

					select {
					case <-watch:
					case <-ctx.Done():
						return nil
					}
				}
			},
		),
	)
}

func (pn *PrivateNetworks) newInterface(name string, dev *dptables.Device) tables.PrivateNetworkInterface {
	iface := tables.PrivateNetworkInterface{Name: name}

	switch {
	case dev == nil:
		iface.Error = fmt.Sprintf("Interface %q not found", name)
	case !dev.Selected:
		iface.Error = fmt.Sprintf("Interface %q not selected by Cilium: %v", name, dev.NotSelectedReason)
	default:
		iface.Index = dev.Index
	}

	return iface
}
