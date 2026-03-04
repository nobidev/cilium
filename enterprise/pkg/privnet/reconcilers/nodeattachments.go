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
	"iter"
	"log/slog"
	"maps"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	"github.com/cilium/cilium/pkg/datapath/linux/device"
	dptables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/k8s"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	cs_iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/promise"
)

// NodeAttachmentCell provides reconcilers
var NodeAttachmentCell = cell.Group(
	cell.ProvidePrivate(
		tables.NewNodeAttachmentsTable,
	),

	cell.Provide(
		statedb.RWTable[*tables.NodeAttachment].ToTable,
		newNodeAttachments,
	),

	// Invoke reconcilers
	cell.Invoke(
		(*nodeAttachments).registerReconciler,
		(*nodeAttachments).registerK8sReflector,
		(*nodeAttachments).reconcileNodeSelector,
		(*nodeAttachments).registerConflictResolver,
		(*nodeAttachments).triggerFinalizers,
	),
)

type nodeAttachments struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config
	db  *statedb.DB

	tbl    statedb.RWTable[*tables.NodeAttachment]
	nodes  statedb.Table[*node.LocalNode]
	client cs_iso_v1alpha1.PrivateNetworkNodeAttachmentInterface

	desiredDevManager device.ManagerOperations
}

func newNodeAttachments(in struct {
	cell.In

	Log             *slog.Logger
	JobGroup        job.Group
	Config          config.Config
	DB              *statedb.DB
	NodeAttachments statedb.RWTable[*tables.NodeAttachment]
	Nodes           statedb.Table[*node.LocalNode]
	DeviceManager   device.ManagerOperations
	Client          client.Clientset
}) (*nodeAttachments, error) {
	reconciler := &nodeAttachments{
		log:               in.Log,
		jg:                in.JobGroup,
		cfg:               in.Config,
		db:                in.DB,
		tbl:               in.NodeAttachments,
		nodes:             in.Nodes,
		desiredDevManager: in.DeviceManager,
	}

	if !in.Config.IsLocallyConnected() {
		return reconciler, nil
	}

	if !in.Client.IsEnabled() {
		return nil, errors.New("private networks requires Kubernetes support to be enabled")
	}

	reconciler.client = in.Client.IsovalentV1alpha1().PrivateNetworkNodeAttachments()
	return reconciler, nil
}

func (na *nodeAttachments) registerReconciler(
	cfg config.Config,
	params reconciler.Params,
	devices statedb.Table[*dptables.Device],
) error {
	if !cfg.IsLocallyConnected() {
		return nil
	}

	_, err := reconciler.Register(
		params,
		na.tbl,
		(*tables.NodeAttachment).Clone,
		(*tables.NodeAttachment).SetDeviceCreationStatus,
		(*tables.NodeAttachment).GetDeviceCreationStatus,
		&nodeAttachmentOps{
			log:               na.log,
			devices:           devices,
			deviceOwner:       na.desiredDevManager.GetOrRegisterOwner("privnet-node-attachments"),
			desiredDevManager: na.desiredDevManager,
		},
		nil,
		reconciler.WithoutPruning(),
	)
	return err
}

func (na *nodeAttachments) triggerFinalizers() {
	if !na.cfg.IsLocallyConnected() {
		return
	}

	initializer := na.desiredDevManager.RegisterInitializer("private-networks")

	na.jg.Add(job.OneShot("attachment-finalizer-sync", func(ctx context.Context, health cell.Health) error {
		health.OK("Waiting for table initialization")

		wait := NewWaitUntilReconciledFn(na.db, na.tbl, (*tables.NodeAttachment).GetDeviceCreationStatus)
		if err := wait(ctx); err != nil {
			return err
		}
		na.desiredDevManager.FinalizeInitializer(initializer)
		return nil
	}))
}

func (na *nodeAttachments) registerK8sReflector(sync promise.Promise[synced.CRDSync]) error {
	if !na.cfg.IsLocallyConnected() {
		return nil
	}

	cfg := k8s.ReflectorConfig[*tables.NodeAttachment]{
		Name:          "to-table", // the full name will be "job-k8s-reflector-privnet-node-attachments-to-table"
		Table:         na.tbl,
		ListerWatcher: utils.ListerWatcherFromTyped(na.client),
		MetricScope:   iso_v1alpha1.PrivateNetworkNodeAttachmentKindDefinition,
		CRDSync:       sync,
		TransformMany: func(txn statedb.ReadTxn, deleted bool, obj any) (toInsert, toDelete iter.Seq[*tables.NodeAttachment]) {
			attachObj, ok := obj.(*iso_v1alpha1.PrivateNetworkNodeAttachment)
			if !ok {
				return nil, nil
			}

			var nodeLabels slim_labels.Set
			if ln, _, found := na.nodes.Get(txn, node.LocalNodeQuery); found {
				nodeLabels = ln.Labels
			}

			stale := na.tbl.Prefix(txn, tables.NodeAttachmentByResource(types.PrivateNetworkResource{
				Kind: iso_v1alpha1.PrivateNetworkNodeAttachmentKindDefinition,
				Name: attachObj.Name,
			}))
			if deleted {
				return nil, statedb.ToSeq(stale)
			}

			desired := make(map[tables.NodeAttachmentPrimaryKey]*tables.NodeAttachment)
			for _, deviceObj := range attachObj.Spec.Attachments {
				dev := &tables.NodeAttachment{
					Resource: types.PrivateNetworkResource{
						Kind: iso_v1alpha1.PrivateNetworkNodeAttachmentKindDefinition,
						Name: attachObj.Name,
					},
					Network: tables.NetworkName(attachObj.Spec.PrivateNetworkRef.Name),
				}

				// update configured subnets
				for _, subnetRef := range deviceObj.SubnetRefs {
					dev.Subnets = append(dev.Subnets, tables.SubnetName(subnetRef.Name))
				}

				// update node selector labels and status
				selector, err := slim_meta_v1.LabelSelectorAsSelector(&attachObj.Spec.NodeSelector)
				if err != nil {
					na.log.Warn("failed to parse node selector, setting match nothing selector", logfields.Error, err)
					selector = slim_labels.Nothing()
				}

				dev.NodeSelector = tables.NodeSelector{
					Selector:        selector,
					SelectorMatches: selector.Matches(nodeLabels),
				}

				// device name and type are set based on VLAN configuration
				if deviceObj.VlanID == nil {
					dev.Type = tables.DeviceTypeUserManaged
					dev.Name = tables.DeviceName(deviceObj.Interface)
				} else {
					dev.Type = tables.DeviceTypeCiliumManaged
					dev.Config = tables.DeviceConfiguration{
						ParentInterfaceName: tables.DeviceName(deviceObj.Interface),
						VLANID:              *deviceObj.VlanID,
					}
					dev.Name = dev.Config.GetDeviceName()
				}

				desired[dev.Key()] = dev
			}

			current := make(map[tables.NodeAttachmentPrimaryKey]*tables.NodeAttachment)
			for _, dev := range desired {
				// getAttachmentConflicts will update dev as well as any
				// other attachment which may get into conflict due to this change.
				// Note, this does not account for stale entries so we may end up marking
				// a device as conflicting temporarily. Once stale entries are removed, dedicated
				// conflict detector reconciler will remove conflict state.
				updates := na.getAttachmentConflicts(txn, dev, desired)
				for _, update := range updates {
					update.OpsStatus = reconciler.StatusPending()
					current[update.Key()] = update
				}
			}

			filter := func(obj *tables.NodeAttachment) bool {
				_, ok := current[obj.Key()]
				return !ok
			}

			return maps.Values(current), statedb.ToSeq(statedb.Filter(stale, filter))
		},
	}

	return k8s.RegisterReflector(na.jg, na.db, cfg)
}

func (na *nodeAttachments) reconcileNodeSelector() {
	if !na.cfg.IsLocallyConnected() {
		return
	}

	wtx := na.db.WriteTxn(na.tbl)
	initialized := na.tbl.RegisterInitializer(wtx, "node-selector-initialized")
	wtx.Commit()

	na.jg.Add(job.OneShot(
		"reconcile-attachment-node-selector",
		func(ctx context.Context, health cell.Health) error {
			health.OK("Starting")

			var (
				initDone   bool
				nodeLabels slim_labels.Set
			)

			for {
				var watchset = statedb.NewWatchSet()

				txn := na.db.WriteTxn(na.tbl)
				localNode, _, nodeWatch, found := na.nodes.GetWatch(txn, node.LocalNodeQuery)
				watchset.Add(nodeWatch)

				// Check for node label change. If node labels are updated we trigger re-evaluation
				// of all entries.
				if found && !maps.Equal(nodeLabels, localNode.Labels) {
					nodeLabels = localNode.Labels

					for attach := range na.tbl.All(txn) {
						selectorMatches := attach.NodeSelector.Selector.Matches(nodeLabels)
						if selectorMatches == attach.NodeSelector.SelectorMatches {
							continue
						}

						toUpdate := attach.Clone()
						toUpdate.NodeSelector.SelectorMatches = selectorMatches
						toUpdate.OpsStatus = reconciler.StatusPending()

						_, _, err := na.tbl.Insert(txn, toUpdate)
						if err != nil {
							txn.Abort()
							return err
						}

						for _, toUpdate := range na.getAttachmentConflicts(txn, attach, nil) {
							toUpdate.OpsStatus = reconciler.StatusPending()
							_, _, err := na.tbl.Insert(txn, toUpdate)
							if err != nil {
								txn.Abort()
								return err
							}
						}
					}
				}

				if !initDone {
					localNodeInit, initWatch := na.nodes.Initialized(txn)
					if !localNodeInit {
						watchset.Add(initWatch)
					} else {
						initDone = true
						initialized(txn)
					}
				}

				txn.Commit()

				health.OK("Reconciliation completed")

				_, err := watchset.Wait(ctx, SettleTime)
				if err != nil {
					return err
				}
			}
		}))
}

func (na *nodeAttachments) registerConflictResolver() {
	if !na.cfg.IsLocallyConnected() {
		return
	}

	na.jg.Add(
		job.OneShot("node-attachment-conflict-resolver",
			na.conflictResolver,
		),
	)
}

func (na *nodeAttachments) conflictResolver(ctx context.Context, health cell.Health) error {
	health.OK("Starting")

	var (
		watchset = statedb.NewWatchSet()
		closed   []<-chan struct{}
		err      error

		tracker     = newWatchesTracker[tables.DeviceName]()
		conflicting = sets.New[tables.DeviceName]()
		conflicts   = -1
	)

	wtx := na.db.WriteTxn(na.tbl)
	tblIter, _ := na.tbl.Changes(wtx)
	wtx.Commit()

	for {
		toProcess := sets.New[tables.DeviceName]()
		changes, watch := tblIter.Next(na.db.ReadTxn())
		watchset.Add(watch)

		for change := range changes {
			// this reconcilers' main job is to resolve conflict, so process objects which
			// are marked as conflicting.
			if change.Object.Conflict == tables.AttachmentConflictNetworks {
				toProcess.Insert(change.Object.Name)
			}
		}

		for devName := range tracker.Iter(closed) {
			toProcess.Insert(devName)
		}

		if toProcess.Len() > 0 {
			txn := na.db.WriteTxn(na.tbl)

			for devName := range toProcess {
				attachments, devWatch := na.tbl.ListWatch(txn, tables.NodeAttachmentsByDeviceName(devName))
				attachmentsByDevName := statedb.Collect(attachments)
				if len(attachmentsByDevName) == 0 {
					conflicting.Delete(devName)
					continue
				}

				selected := 0
				for _, attachment := range attachmentsByDevName {
					if attachment.NodeSelector.SelectorMatches {
						selected++
					}
				}

				if selected > 1 {
					conflicting.Insert(devName)
					watchset.Add(devWatch)
					tracker.Register(devWatch, devName)
				} else {
					conflicting.Delete(devName)
				}

				updates := na.getAttachmentConflicts(txn, attachmentsByDevName[0], nil)
				for _, update := range updates {
					update.OpsStatus = reconciler.StatusPending()
					_, _, err = na.tbl.Insert(txn, update)
					if err != nil {
						txn.Abort()
						return err
					}
				}
			}

			txn.Commit()
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

// getAttachmentConflicts returns attachments that need a conflict status update for obj, evaluating
// both existing entries from the node-attachments table and optional pending entries that are not
// yet inserted into the table.
func (na *nodeAttachments) getAttachmentConflicts(
	txn statedb.ReadTxn,
	obj *tables.NodeAttachment,
	pending map[tables.NodeAttachmentPrimaryKey]*tables.NodeAttachment,
) []*tables.NodeAttachment {
	attachments := map[tables.NodeAttachmentPrimaryKey]*tables.NodeAttachment{
		obj.Key(): obj, // include obj with latest state
	}
	for attach := range na.tbl.List(txn, tables.NodeAttachmentsByDeviceName(obj.Name)) {
		if attach.Key() != obj.Key() {
			attachments[attach.Key()] = attach
		}
	}
	for key, attach := range pending {
		if key == obj.Key() || attach.Name != obj.Name {
			continue
		}
		attachments[key] = attach
	}

	alreadySelected := false
	selectedConflict := tables.AttachmentConflictNone
	for _, attach := range attachments {
		if attach.NodeSelector.SelectorMatches {
			if alreadySelected {
				selectedConflict = tables.AttachmentConflictNetworks
				break
			}
			alreadySelected = true
		}
	}

	updates := []*tables.NodeAttachment{}
	for _, attach := range attachments {
		newConflict := tables.AttachmentConflictNone
		if attach.NodeSelector.SelectorMatches {
			newConflict = selectedConflict
		}
		if attach.Conflict != newConflict {
			cp := attach.Clone()
			cp.Conflict = newConflict
			updates = append(updates, cp)
		}
	}
	return updates
}

var _ reconciler.Operations[*tables.NodeAttachment] = &nodeAttachmentOps{}

type nodeAttachmentOps struct {
	log *slog.Logger

	devices           statedb.Table[*dptables.Device]
	deviceOwner       device.DeviceOwner
	desiredDevManager device.ManagerOperations
}

func (ops *nodeAttachmentOps) Update(ctx context.Context, txn statedb.ReadTxn, rev statedb.Revision, obj *tables.NodeAttachment) error {
	if !obj.IsManagedDevice() {
		return ops.Delete(ctx, txn, rev, obj)
	}

	// check if parent interface exists
	if obj.Config.ParentInterfaceName == "" {
		return fmt.Errorf("parent interface name not specified")
	}

	// TODO: hardening required.
	// There are couple of cases where reconciliation need to be retriggered, for eg, parent device might be down at the time
	// of this processing or parent device idx changes (due to device removal/addition).
	parentDevice, _, exists := ops.devices.Get(txn, dptables.DeviceNameIndex.Query(string(obj.Config.ParentInterfaceName)))
	if !exists || parentDevice.Index == 0 {
		return fmt.Errorf("%q not found", obj.Config.ParentInterfaceName)
	}

	desiredDevice := device.DesiredDevice{
		Owner:      ops.deviceOwner,
		Name:       string(obj.Name),
		DeviceSpec: newDesiredVLANDeviceSpec(obj, parentDevice.Index),
	}

	err := ops.desiredDevManager.UpsertDevice(desiredDevice)
	if err != nil {
		return err
	}

	ops.log.Debug("added private-network device",
		logfields.ClusterwidePrivateNetwork, obj.Network,
		logfields.PrivateNetworkAttachment, obj.Name,
	)

	return nil
}

func (ops *nodeAttachmentOps) Delete(_ context.Context, txn statedb.ReadTxn, _ statedb.Revision, obj *tables.NodeAttachment) error {
	dev := device.DesiredDevice{
		Owner:      ops.deviceOwner,
		Name:       string(obj.Name),
		DeviceSpec: newDesiredVLANDeviceSpec(obj, 0), // parent device ifindex is not relevant for deletion
	}

	return ops.desiredDevManager.DeleteDevice(dev)
}

func (*nodeAttachmentOps) Prune(_ context.Context, _ statedb.ReadTxn, _ iter.Seq2[*tables.NodeAttachment, statedb.Revision]) error {
	// all cleanups are managed by deletes
	return nil
}

func newDesiredVLANDeviceSpec(obj *tables.NodeAttachment, parentIdx int) *device.DesiredVLANDeviceSpec {
	return &device.DesiredVLANDeviceSpec{
		Name:        string(obj.Name),
		VLANID:      obj.Config.VLANID,
		ParentName:  string(obj.Config.ParentInterfaceName),
		ParentIndex: parentIdx,
	}
}
