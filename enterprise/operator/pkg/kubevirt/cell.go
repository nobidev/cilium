//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

// Package kubevirt is responsible for supporting the migration of KubeVirt VM pods
// if they are running in bridge networking mode and have the "kubevirt.io/allow-pod-bridge-network-live-migration"
// annotation.
//
// Migration works by relying on the `ipmigration` package, which allows the target pod to become
// ready in detached state (and thus allowing KubeVirt to transfer VM state) without having to
// perform an IPAM IP request for the IP still in use by the source VM pod. The main job of therefore
// is to detach/attach KubeVirt VM pods based on their migration state. This works as follows:
//
// All pods belonging to the same KubeVirt VM (as indicated by the "vm.kubevirt.io/name" pod label)
// are grouped together. This cell then determines which of these pods is considered the primary pod,
// i.e. the pod currently designated to receive the VM's traffic. The primary pod is determined based on
// two pod properties:
//
//  1. The primary pod must have a "kubevirt.io/nodeName" label whose value matches the name of the K8s node the
//     pod is currently running on. This is the main indicator from KubeVirt that the pod is the one which should
//     receive traffic.
//  2. Any pod which looks like to be the new primary must have a "kubevirt.io/migration-target-ready-timestamp"
//     annotation which contains a more recent timestamp than the previous primary. This ensures that we are not
//     flapping between the new and old primary while the "kubevirt.io/nodeName" label is updated on both pods.
//
// Once the set of pods and the primary is calculated, the cell then sets the "cni.v1alpha1.isovalent.com/detached" on
// all non-primary pods, and ensures the primary pod is attached by removing the same annotation on the primary pod if
// present. This way, we ensure that the primary pod is the only attached pod of the set of pods belonging to a KubeVirt
// VM and thus is the only pod able to receive traffic. During a migration, this means that the target pod starts in
// detached mode, once it becomes the primary however we attach it and detach the source pod.
package kubevirt

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/cilium/cilium/enterprise/pkg/ipmigration/types"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

var Cell = cell.Module(
	"kubevirt-vm-migration",
	"Enterprise KubeVirt VM migration support",

	cell.Config(defaultConfig),

	cell.Provide(NewKubeVirtVMTable),
	cell.ProvidePrivate(newVmReconcilerOps),
	cell.Invoke(
		newMigrator,
		registerReconciler,
	),
)

const (
	kubeVirtAllowMigrationAnnotation = "kubevirt.io/allow-pod-bridge-network-live-migration"
	kubeVirtReadyTimeAnnotation      = "kubevirt.io/migration-target-ready-timestamp"
	kubeVirtNodeNameLabel            = "kubevirt.io/nodeName"
	kubeVirtVMNameLabel              = "vm.kubevirt.io/name"

	logfieldVM         = "vm"
	logfieldNewVM      = "newvm"
	logfieldOldVM      = "oldvm"
	logfieldPrimaryPod = "primaryPod"
)

const kubeVirtTimeFormat = "2006-01-02 15:04:05.999999999 -0700 MST"

const vmTablePodSyncInitializer = "pod-sync-initializer"

// Config registers a command-line flag on the operator to enable this subsystem
type Config struct {
	EnableKubeVirtVMMigration bool
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-kubevirt-vm-migration", c.EnableKubeVirtVMMigration, "Enable support for kubevirt VM migration (beta)")
	flags.MarkHidden("enable-kubevirt-vm-migration")
}

var defaultConfig = Config{
	EnableKubeVirtVMMigration: false,
}

type migratorParams struct {
	cell.In

	Pods resource.Resource[*slim_corev1.Pod]

	StateDB *statedb.DB
	VMTable statedb.RWTable[*KubeVirtVM]

	JobGroup job.Group
	Log      *slog.Logger

	Config Config
}

type migrator struct {
	log           *slog.Logger
	db            *statedb.DB
	vmTable       statedb.RWTable[*KubeVirtVM]
	podInitalizer func(statedb.WriteTxn)
}

// newMigrator creates a new KubeVirt VM migrator
func newMigrator(params migratorParams) *migrator {
	if !params.Config.EnableKubeVirtVMMigration {
		return nil
	}

	txn := params.StateDB.WriteTxn(params.VMTable)
	podInitalizer := params.VMTable.RegisterInitializer(txn, vmTablePodSyncInitializer)
	txn.Commit()

	m := &migrator{
		log: params.Log,

		db:      params.StateDB,
		vmTable: params.VMTable,

		podInitalizer: podInitalizer,
	}

	params.JobGroup.Add(job.Observer("kubevirt-migration-pod-watcher",
		func(ctx context.Context, event resource.Event[*slim_corev1.Pod]) error {
			m.handlePodEvent(event)
			event.Done(nil)
			return nil
		},
		params.Pods,
	))

	return m
}

// handlePodEvent observes pod updates and if it determines that the pod belongs to a migratable KubeVirt VM, will
// add it to the KubeVirtVM table.
func (m *migrator) handlePodEvent(event resource.Event[*slim_corev1.Pod]) {
	if event.Kind == resource.Sync {
		txn := m.db.WriteTxn(m.vmTable)
		m.podInitalizer(txn)
		txn.Commit()
		return
	}

	// Only consider pods which support KubeVirt bridge network migration
	_, ok := event.Object.Annotations[kubeVirtAllowMigrationAnnotation]
	if !ok {
		return // ignored
	}

	vmName, ok := event.Object.Labels[kubeVirtVMNameLabel]
	if !ok {
		return // ignored
	}
	vmKey := resource.Key{
		Name:      vmName,
		Namespace: event.Object.Namespace,
	}

	primaryNodeName, ok := event.Object.Labels[kubeVirtNodeNameLabel]
	if !ok {
		m.log.Debug("kubevirt pod without node name label",
			logfields.Pod, event.Key)
		return
	}

	switch event.Kind {
	case resource.Delete:
		m.removePodFromVM(event.Key, vmKey)
	case resource.Upsert:
		m.addPodToVM(event.Object, vmKey, primaryNodeName)
	}
}

// extractIPPair extracts the IP address of a pod. It may return an empty object if the pod does not yet have any IPs.
func (m *migrator) extractIPPair(pod *slim_corev1.Pod) types.DetachedIpamAddressPair {
	result := types.DetachedIpamAddressPair{}
	for _, podIP := range pod.Status.PodIPs {
		ip, err := netip.ParseAddr(podIP.IP)
		if err != nil {
			m.log.Error("unexpected invalid pod IP in pod status",
				logfields.Error, err,
				logfields.Pod, pod.Namespace+"/"+pod.Name)
			continue
		}

		switch {
		case ip.Is4():
			result.IPV4 = &ip
		case ip.Is6():
			result.IPV6 = &ip
		}
	}

	return result
}

// removePodFromVM disassociates a pod from the given VM. If this was the last pod referencing the VM object, the
// object is deleted. We do not need to update any annotations when pods are deleted. This function may unset the
// primary pod of a VM, but we will only update pod annotations once a new primary has been detected.
func (m *migrator) removePodFromVM(pod, vmKey resource.Key) {
	txn := m.db.WriteTxn(m.vmTable)
	defer txn.Commit()

	vm, _, ok := m.vmTable.Get(txn, KubeVirtVMNameIndex.Query(vmKey))
	if !ok {
		m.log.Warn("pod deletion event for unknown VM",
			logfields.Pod, pod,
			logfieldVM, vmKey)
		return
	}

	vm = vm.DeepCopy()
	vm.Pods = slices.DeleteFunc(vm.Pods, func(tableKey resource.Key) bool {
		return pod == tableKey
	})
	if vm.PrimaryPod == pod {
		vm.PrimaryPod = resource.Key{}
	}

	var err error
	if len(vm.Pods) == 0 {
		_, _, err = m.vmTable.Delete(txn, vm)
	} else {
		_, _, err = m.vmTable.Insert(txn, vm)
	}
	if err != nil {
		// This should never happen in practice
		m.log.Error("BUG: Internal error while attempting to update kubevirt VM state. "+
			"Please report this bug to Cilium developers.",
			logfields.Error, err)
	}
}

// addPodToVM associates a kubevirt launcher pod with a kubevirt VM. If we detect that the VM has been migrating
// to a new pod, this will trigger the reconciler to update the pod annotations accordingly.
func (m *migrator) addPodToVM(pod *slim_corev1.Pod, vmKey resource.Key, primaryNodeName string) {
	txn := m.db.WriteTxn(m.vmTable)
	defer txn.Commit()

	podKey := resource.Key{
		Name:      pod.Name,
		Namespace: pod.Namespace,
	}

	var newVM *KubeVirtVM
	oldVM, _, ok := m.vmTable.Get(txn, KubeVirtVMNameIndex.Query(vmKey))
	if ok {
		newVM = oldVM.DeepCopy()
	} else {
		newVM = &KubeVirtVM{
			VMName: vmKey,
			Status: reconciler.StatusDone(), // only trigger reconciler once IPAM information is valid
		}
	}

	// Add pod as VM owner
	if !slices.Contains(newVM.Pods, podKey) {
		newVM.Pods = append(newVM.Pods, podKey)
	}

	var targetReady time.Time
	targetReadyStr, ok := pod.Annotations[kubeVirtReadyTimeAnnotation]
	if ok {
		var err error
		targetReady, err = time.Parse(kubeVirtTimeFormat, targetReadyStr)
		if err != nil {
			m.log.Warn("unable to parse "+kubeVirtReadyTimeAnnotation+" as a timestamp.",
				logfields.Error, err,
				logfields.Pod, podKey)
			return
		}
	}

	// Check if upserted pod is new primary pod
	isNewPrimary := pod.Spec.NodeName == primaryNodeName &&
		(oldVM == nil || !oldVM.PrimaryReadyTime.After(targetReady))

	if isNewPrimary {
		newVM.PrimaryPod = podKey
		newVM.PrimaryReadyTime = targetReady

		newIPAM := m.extractIPPair(pod)
		if newIPAM.IsValid() {
			newVM.IPAM = newIPAM
		}
	}

	// Pod have changed and/or IPAM is become available,
	// trigger the reconciler to detach the old primary and attach the new one
	if !newVM.equals(oldVM) && newVM.IPAM.IsValid() {
		newVM.Status = reconciler.StatusPending()
	}

	m.log.Debug("Updating kubevirt VM",
		logfieldNewVM, newVM,
		logfieldOldVM, oldVM)

	_, _, err := m.vmTable.Insert(txn, newVM)
	if err != nil {
		// This should never happen in practice
		m.log.Error("BUG: Internal error while attempting to update kubevirt VM state. "+
			"Please report this bug to Cilium developers.",
			logfields.Error, err)
	}
}

func registerReconciler(cfg Config, p reconciler.Params, ops *vmReconcilerOps, vm statedb.RWTable[*KubeVirtVM]) (reconciler.Reconciler[*KubeVirtVM], error) {
	if !cfg.EnableKubeVirtVMMigration {
		return nil, nil
	}

	return reconciler.Register(
		p,
		vm,
		// clone
		func(vm *KubeVirtVM) *KubeVirtVM {
			// shallow copy
			var vm2 = *vm
			return &vm2
		},
		// setStatus
		func(vm *KubeVirtVM, status reconciler.Status) *KubeVirtVM {
			vm.Status = status
			return vm
		},
		// getStatus
		func(vm *KubeVirtVM) reconciler.Status {
			return vm.Status
		},
		ops,
		nil,
		reconciler.WithoutPruning(),
	)
}

type vmReconcilerOps struct {
	log       *slog.Logger
	clientset kubernetes.Interface
}

func newVmReconcilerOps(cfg Config, log *slog.Logger, clientset k8sClient.Clientset) *vmReconcilerOps {
	if !cfg.EnableKubeVirtVMMigration {
		return nil
	}

	return &vmReconcilerOps{log: log, clientset: clientset}
}

// Update implements reconciler.Operations[*KubeVirtVM]
func (v *vmReconcilerOps) Update(ctx context.Context, txn statedb.ReadTxn, vm *KubeVirtVM) error {
	v.log.Info("Reconciling pod annotations for KubeVirt VM",
		logfieldPrimaryPod, vm.PrimaryPod,
		logfieldVM, vm.VMName)

	if !vm.IPAM.IsValid() {
		return fmt.Errorf("reconciliation was triggerd with invalid IPAM for VM %s", vm.VMName.String())
	}

	ipamValue, err := json.Marshal(vm.IPAM)
	if err != nil {
		return fmt.Errorf("failed to marshal VM IPAM data: %w", err)
	}

	delAnnotationPatch := fmt.Sprintf(`{"metadata":{"annotations":{%q:null}}}`, types.DetachedAnnotation)
	addAnnotationPatch := fmt.Sprintf(`{"metadata":{"annotations":{%q:%q}}}`, types.DetachedAnnotation, ipamValue)

	for _, pod := range vm.Pods {
		var (
			patch  string
			action string
		)
		if pod == vm.PrimaryPod {
			// remove detach annotation from primary
			patch = delAnnotationPatch
			action = "attach-pod"
		} else {
			// add detach annotation to non-primary
			patch = addAnnotationPatch
			action = "detach-pod"
		}

		// Patch the Pod's annotations
		v.log.Debug("Patching "+types.DetachedAnnotation+" annotation on VM pod",
			logfieldVM, vm.VMName,
			logfields.Pod, pod.Namespace+"/"+pod.Name,
			logfields.Action, action,
		)
		_, err = v.clientset.CoreV1().Pods(pod.Namespace).Patch(
			ctx,
			pod.Name,
			k8sTypes.StrategicMergePatchType,
			[]byte(patch),
			metav1.PatchOptions{},
		)
		if err != nil {
			return fmt.Errorf("failed to update pod annotations of pod %s: %w", pod, err)
		}
	}

	return nil
}

// Delete implements reconciler.Operations[*KubeVirtVM]
func (v *vmReconcilerOps) Delete(ctx context.Context, txn statedb.ReadTxn, vm *KubeVirtVM) error {
	return nil // nothing to do if all VM pods have been deleted
}

// Prune implements reconciler.Operations[*KubeVirtVM]
func (v *vmReconcilerOps) Prune(ctx context.Context, txn statedb.ReadTxn, vms iter.Seq2[*KubeVirtVM, statedb.Revision]) error {
	return nil // nothing to do (see Delete)
}
