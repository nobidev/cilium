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
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/reconcilers/idpool"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/vni"
	dptables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/k8s"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	cs_iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
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
		idpool.NewPrivnetIDPool,

		// Provides the ReadOnly PrivateNetworks table.
		statedb.RWTable[tables.PrivateNetwork].ToTable,
	),

	cell.Invoke(
		// Registers the k8s to table reflector.
		(*PrivateNetworks).registerK8sReflector,

		// Register the reconciler reacting to device changes.
		(*PrivateNetworks).registerDeviceChangesReconciler,

		// Register the reconciler reacting to interface conflicts.
		(*PrivateNetworks).registerInterfaceConflictsReconciler,

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

func (pn *PrivateNetworks) registerK8sReflector(idpool *idpool.NetworkIDPool, sync promise.Promise[synced.CRDSync]) error {
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
				id, err = idpool.Acquire(tables.NetworkName(privnet.Name))
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

				// Verify if any other network is selecting the same interface.
				var conflict bool
				for net := range pn.tbl.List(txn, tables.PrivateNetworksByInterface(ifname)) {
					if net.Name != tables.NetworkName(privnet.Name) {
						conflict = true
						break
					}
				}

				iface = pn.newInterface(ifname, dev, conflict)
			}

			vni := pn.extractVNI(privnet)
			inbs := pn.extractINBs(privnet)
			subnets := pn.extractSubnets(privnet)

			return tables.PrivateNetwork{
				Name:      tables.NetworkName(privnet.Name),
				VNI:       vni,
				ID:        id,
				INBs:      inbs,
				Interface: iface,
				Subnets:   subnets,
			}, true
		},
	}

	return k8s.RegisterReflector(pn.jg, pn.db, cfg)
}

func (pn *PrivateNetworks) extractINBs(privnet *iso_v1alpha1.ClusterwidePrivateNetwork) tables.PrivateNetworkINBs {
	selectors := make(map[tables.ClusterName]tables.PrivateNetworkINBNodeSelector, len(privnet.Spec.INBs))
	for _, candidate := range privnet.Spec.INBs {
		selector, err := slim_metav1.LabelSelectorAsSelector(&candidate.NodeSelector.LabelSelector)
		if err != nil {
			pn.log.Error("Encountered invalid INB node selector for cluster",
				logfields.Error, err,
				logfields.ClusterwidePrivateNetwork, privnet.Name,
				logfields.ClusterName, candidate.Cluster,
			)
			continue
		}

		// Cannot happen by construction (the label selector is never nil), but
		// better safe than sorry...
		if selector == labels.Nothing() {
			continue
		}

		selectors[tables.ClusterName(candidate.Cluster)] = tables.PrivateNetworkINBNodeSelector{Selector: selector}
	}
	return tables.PrivateNetworkINBs{Selectors: selectors}
}

func (pn *PrivateNetworks) extractRoutes(privnet tables.NetworkName, subnet iso_v1alpha1.SubnetSpec) []tables.PrivateNetworkRoute {
	routes := make([]tables.PrivateNetworkRoute, 0, len(subnet.Routes))
	for _, routeSpec := range subnet.Routes {
		dst, err := netip.ParsePrefix(string(routeSpec.Destination))
		if err != nil {
			pn.log.Error("Encountered invalid route destination in private network spec",
				logfields.CIDR, routeSpec.Destination,
				logfields.Error, err,
				logfields.ClusterwidePrivateNetwork, privnet,
				logfields.PrivateNetworkSubnet, subnet.Name,
			)
			continue
		}

		if routeSpec.Gateway == iso_v1alpha1.EVPNRoute {
			routes = append(routes, tables.PrivateNetworkRoute{
				Destination: dst,
				EVPNGateway: true,
			})
			continue
		}

		gw, err := netip.ParseAddr(string(routeSpec.Gateway))
		if err != nil {
			pn.log.Error("Encountered invalid route gateway in private network spec",
				logfields.IPAddr, routeSpec.Gateway,
				logfields.Error, err,
				logfields.ClusterwidePrivateNetwork, privnet,
				logfields.PrivateNetworkSubnet, subnet.Name,
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
		subnet := tables.PrivateNetworkSubnet{
			Name: tables.SubnetName(subnetPrefix.Name),
		}

		if subnetPrefix.CIDRv4 != "" {
			cidr, err := netip.ParsePrefix(string(subnetPrefix.CIDRv4))
			if err != nil || !cidr.Addr().Is4() {
				pn.log.Error("Encountered invalid IPv4 subnet CIDR in private network spec",
					logfields.CIDR, subnetPrefix.CIDRv4,
					logfields.Error, err,
					logfields.ClusterwidePrivateNetwork, privnet.Name,
					logfields.PrivateNetworkSubnet, subnetPrefix.Name,
				)
			} else {
				subnet.CIDRv4 = cidr
			}
		}

		if subnetPrefix.CIDRv6 != "" {
			cidrv6, err := netip.ParsePrefix(string(subnetPrefix.CIDRv6))
			if err != nil || !cidrv6.Addr().Is6() {
				pn.log.Error("Encountered invalid IPv6 subnet CIDR in private network spec",
					logfields.CIDR, subnetPrefix.CIDRv6,
					logfields.Error, err,
					logfields.ClusterwidePrivateNetwork, privnet.Name,
					logfields.PrivateNetworkSubnet, subnetPrefix.Name,
				)
			} else {
				subnet.CIDRv6 = cidrv6
			}
		}

		subnet.Routes = pn.extractRoutes(tables.NetworkName(privnet.Name), subnetPrefix)
		if subnet.CIDRv4.IsValid() || subnet.CIDRv6.IsValid() {
			subnets = append(subnets, subnet)
		}
	}
	return subnets
}

func (pn *PrivateNetworks) extractVNI(privnet *iso_v1alpha1.ClusterwidePrivateNetwork) vni.VNI {
	if privnet.Status != nil && privnet.Status.VNI != nil {
		res, err := vni.FromUint32(*privnet.Status.VNI)
		if err != nil {
			pn.log.Error("Encountered invalid VNI in private network status",
				logfields.Error, err,
				logfields.ClusterwidePrivateNetwork, privnet.Name,
				vni.LogFieldVNI, *privnet.Status.VNI,
			)
		}
		return res
	}
	return vni.VNI{}
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

			iface := pn.newInterface(ifname, devs[ifname], privnet.Interface.Conflict)
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

func (pn *PrivateNetworks) registerInterfaceConflictsReconciler() {
	// Interfaces are currently only relevant in bridge mode.
	if !pn.cfg.EnabledAsBridge() {
		return
	}

	pn.jg.Add(
		job.OneShot(
			"private-networks-interface-conflicts",
			pn.reconcileInterfaceConflicts,
		),
	)
}

func (pn *PrivateNetworks) reconcileInterfaceConflicts(ctx context.Context, health cell.Health) error {
	health.OK("Starting")

	type IfName = string
	var (
		watchset = statedb.NewWatchSet()
		closed   []<-chan struct{}
		err      error

		tracker     = newWatchesTracker[IfName]()
		conflicting = sets.New[IfName]()
		conflicts   = -1
	)

	wtx := pn.db.WriteTxn(pn.tbl)
	changeIter, _ := pn.tbl.Changes(wtx)
	wtx.Commit()

	for {
		var toProcess = sets.New[IfName]()

		// We need to use a separate read transaction, because [Next] would panic
		// if called with a WriteTxn that has locked the target table. However,
		// this is fine, because we are only interested in collecting the list of
		// potentially conflicting interfaces, and we'd be simply waken up again
		// if new updates were to happen before acquiring the write transaction.
		changes, watch := changeIter.Next(pn.db.ReadTxn())
		watchset.Add(watch)

		for change := range changes {
			// Check if any new network has been marked as conflicting by the
			// kubernetes reflector. If so, we need to reconcile the already
			// existing network associated with that interface, to mark it as
			// conflicting as well.
			var iface = change.Object.Interface
			if iface.Conflict && !conflicting.Has(iface.Name) {
				toProcess.Insert(iface.Name)
			}
		}

		for ifname := range tracker.Iter(closed) {
			toProcess.Insert(ifname)
		}

		if toProcess.Len() > 0 {
			wtx := pn.db.WriteTxn(pn.tbl)
			for ifname := range toProcess {
				var (
					iter, watch = pn.tbl.ListWatch(wtx, tables.PrivateNetworksByInterface(ifname))
					networks    = statedb.Collect(iter)
					conflict    = len(networks) > 1
				)

				if conflict {
					conflicting.Insert(ifname)
					watchset.Add(watch)
					tracker.Register(watch, ifname)
				} else {
					conflicting.Delete(ifname)
				}

				for _, network := range networks {
					if network.Interface.Conflict != conflict {
						dev, _, _ := pn.devs.Get(wtx, dptables.DeviceNameIndex.Query(ifname))
						network.Interface = pn.newInterface(ifname, dev, conflict)
						pn.tbl.Insert(wtx, network)
					}
				}
			}
			wtx.Commit()
		}

		if conflicts != conflicting.Len() {
			conflicts = conflicting.Len()
			health.OK(fmt.Sprintf("Reconciliation completed, %d conflict(s)", conflicts))
		}

		closed, err = watchset.Wait(ctx, SettleTime)
		if err != nil {
			return err
		}
	}
}

func (pn *PrivateNetworks) registerIDsReleaser(idpool *idpool.NetworkIDPool) {
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
							idpool.Release(change.Object.ID)
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
		job.OneShot(
			"private-networks-id-pool-initialized",
			func(ctx context.Context, health cell.Health) error {
				// Wait for private networks table initialization
				_, watch := pn.tbl.Initialized(pn.db.ReadTxn())
				select {
				case <-watch:
				case <-ctx.Done():
					return ctx.Err()
				}

				idpool.Initialized()
				return nil
			},
		),
	)
}

func (pn *PrivateNetworks) newInterface(name string, dev *dptables.Device, conflict bool) tables.PrivateNetworkInterface {
	iface := tables.PrivateNetworkInterface{Name: name, Conflict: conflict}

	switch {
	case conflict:
		iface.Error = fmt.Sprintf("Interface %q is selected by multiple private networks", name)
	case dev == nil:
		iface.Error = fmt.Sprintf("Interface %q not found", name)
	case dev.OperStatus != "up":
		iface.Error = fmt.Sprintf("Interface %q has %q operational status", name, dev.OperStatus)
	case !dev.Selected:
		iface.Error = fmt.Sprintf("Interface %q not selected by Cilium: %v", name, dev.NotSelectedReason)
	default:
		iface.Index = dev.Index
	}

	return iface
}
