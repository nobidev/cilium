package kubevirt

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cilium/cilium/enterprise/pkg/ipmigration/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func Test_migrator_handlePodEvent(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
	}))

	db := statedb.New()
	vmTable, err := NewKubeVirtVMTable(Config{EnableKubeVirtVMMigration: true}, db)
	require.NoError(t, err)

	initCalled := make(chan struct{}, 1)
	podInitializer := func(txn statedb.WriteTxn) {
		initCalled <- struct{}{}
	}

	m := &migrator{
		log:           log,
		db:            db,
		vmTable:       vmTable,
		podInitalizer: podInitializer,
	}

	sourceVMPod := &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "virt-launcher-testvm-source",
			Namespace: "test-namespace",
			Labels: map[string]string{
				kubeVirtVMNameLabel:   "test-vm",
				kubeVirtNodeNameLabel: "sourcenode",
			},
		},
		Spec: slim_corev1.PodSpec{
			NodeName: "sourcenode",
		},
	}
	sourceVMPodKey := resource.Key{Name: sourceVMPod.Name, Namespace: sourceVMPod.Namespace}

	// Ignore KubeVirt VM pods without the bridge live migration label
	m.handlePodEvent(resource.Event[*slim_corev1.Pod]{
		Kind:   resource.Upsert,
		Key:    sourceVMPodKey,
		Object: sourceVMPod,
		Done: func(err error) {
			assert.NoError(t, err)
		},
	})
	require.Empty(t, statedb.Collect(vmTable.All(db.ReadTxn())))

	// Simulate sync event
	m.handlePodEvent(resource.Event[*slim_corev1.Pod]{
		Kind: resource.Sync,
		Done: func(err error) {
			assert.NoError(t, err)
		},
	})
	<-initCalled

	// Once the pod has the annotation, it should create a VM entry
	sourceVMPod.Annotations = map[string]string{
		kubeVirtAllowMigrationAnnotation: "true",
	}
	m.handlePodEvent(resource.Event[*slim_corev1.Pod]{
		Kind:   resource.Upsert,
		Key:    sourceVMPodKey,
		Object: sourceVMPod,
		Done: func(err error) {
			assert.NoError(t, err)
		},
	})
	vms := statedb.Collect(vmTable.All(db.ReadTxn()))
	require.Len(t, vms, 1)
	require.Equal(t, resource.Key{Name: "test-vm", Namespace: "test-namespace"}, vms[0].VMName)
	require.Equal(t, []resource.Key{sourceVMPodKey}, vms[0].Pods)
	require.Equal(t, sourceVMPodKey, vms[0].PrimaryPod)
	require.Equal(t, reconciler.StatusKindDone, vms[0].Status.Kind)

	// Add pod IPs, this should mark the VM as pending
	sourceVMPod.Status.PodIPs = []slim_corev1.PodIP{
		{IP: "10.20.30.40"},
		{IP: "fe80::1"},
	}
	m.handlePodEvent(resource.Event[*slim_corev1.Pod]{
		Kind:   resource.Upsert,
		Key:    sourceVMPodKey,
		Object: sourceVMPod,
		Done: func(err error) {
			assert.NoError(t, err)
		},
	})
	vms = statedb.Collect(vmTable.All(db.ReadTxn()))
	ipv4 := netip.MustParseAddr("10.20.30.40")
	ipv6 := netip.MustParseAddr("fe80::1")
	require.Len(t, vms, 1)
	require.Equal(t, resource.Key{Name: "test-vm", Namespace: "test-namespace"}, vms[0].VMName)
	require.Equal(t, []resource.Key{sourceVMPodKey}, vms[0].Pods)
	require.Equal(t, sourceVMPodKey, vms[0].PrimaryPod)
	require.Equal(t, types.DetachedIpamAddressPair{
		IPV4: &ipv4,
		IPV6: &ipv6,
	}, vms[0].IPAM)
	require.Equal(t, reconciler.StatusKindPending, vms[0].Status.Kind)

	// Simulate reconciler by setting VM status to Done
	vm := vms[0].DeepCopy()
	vm.Status = reconciler.StatusDone()
	txn := db.WriteTxn(vmTable)
	vmTable.Insert(txn, vm)
	txn.Commit()

	// Create target VM as non-primary
	targetVMPod := &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "virt-launcher-testvm-target",
			Namespace: "test-namespace",
			Labels: map[string]string{
				kubeVirtVMNameLabel:   "test-vm",
				kubeVirtNodeNameLabel: "sourcenode",
			},
			Annotations: map[string]string{
				kubeVirtAllowMigrationAnnotation: "true",
			},
		},
		Spec: slim_corev1.PodSpec{
			NodeName: "targetnode",
		},
		// PodIP intentionally not present in Status
	}
	targetVMPodKey := resource.Key{Name: targetVMPod.Name, Namespace: targetVMPod.Namespace}

	m.handlePodEvent(resource.Event[*slim_corev1.Pod]{
		Kind:   resource.Upsert,
		Key:    targetVMPodKey,
		Object: targetVMPod,
		Done: func(err error) {
			assert.NoError(t, err)
		},
	})
	vms = statedb.Collect(vmTable.All(db.ReadTxn()))
	require.Len(t, vms, 1)
	require.Equal(t, resource.Key{Name: "test-vm", Namespace: "test-namespace"}, vms[0].VMName)
	require.Equal(t, []resource.Key{sourceVMPodKey, targetVMPodKey}, vms[0].Pods)
	require.Equal(t, sourceVMPodKey, vms[0].PrimaryPod)
	require.Equal(t, reconciler.StatusKindPending, vms[0].Status.Kind)

	// Migrate VM to target node (requires label changes on both pods)
	sourceVMPod.Labels[kubeVirtNodeNameLabel] = "targetnode"
	m.handlePodEvent(resource.Event[*slim_corev1.Pod]{
		Kind:   resource.Upsert,
		Key:    sourceVMPodKey,
		Object: sourceVMPod,
		Done: func(err error) {
			assert.NoError(t, err)
		},
	})
	vms = statedb.Collect(vmTable.All(db.ReadTxn()))
	require.Len(t, vms, 1)
	require.Equal(t, resource.Key{Name: "test-vm", Namespace: "test-namespace"}, vms[0].VMName)
	require.Equal(t, []resource.Key{sourceVMPodKey, targetVMPodKey}, vms[0].Pods)
	require.Equal(t, sourceVMPodKey, vms[0].PrimaryPod)
	require.Equal(t, reconciler.StatusKindPending, vms[0].Status.Kind)

	// Update target VM pod label
	targetVMPod.Labels[kubeVirtNodeNameLabel] = "targetnode"
	m.handlePodEvent(resource.Event[*slim_corev1.Pod]{
		Kind:   resource.Upsert,
		Key:    targetVMPodKey,
		Object: targetVMPod,
		Done: func(err error) {
			assert.NoError(t, err)
		},
	})
	vms = statedb.Collect(vmTable.All(db.ReadTxn()))
	require.Len(t, vms, 1)
	require.Equal(t, resource.Key{Name: "test-vm", Namespace: "test-namespace"}, vms[0].VMName)
	require.Equal(t, []resource.Key{sourceVMPodKey, targetVMPodKey}, vms[0].Pods)
	require.Equal(t, targetVMPodKey, vms[0].PrimaryPod)
	require.Equal(t, reconciler.StatusKindPending, vms[0].Status.Kind)

	// Simulate reconciler by setting VM status to Done
	vm = vms[0].DeepCopy()
	vm.Status = reconciler.StatusDone()
	txn = db.WriteTxn(vmTable)
	vmTable.Insert(txn, vm)
	txn.Commit()

	// Remove source pod
	m.handlePodEvent(resource.Event[*slim_corev1.Pod]{
		Kind:   resource.Delete,
		Key:    sourceVMPodKey,
		Object: sourceVMPod,
		Done: func(err error) {
			assert.NoError(t, err)
		},
	})
	vms = statedb.Collect(vmTable.All(db.ReadTxn()))
	require.Len(t, vms, 1)
	require.Equal(t, resource.Key{Name: "test-vm", Namespace: "test-namespace"}, vms[0].VMName)
	require.Equal(t, []resource.Key{targetVMPodKey}, vms[0].Pods)
	require.Equal(t, targetVMPodKey, vms[0].PrimaryPod)
	require.Equal(t, reconciler.StatusKindDone, vms[0].Status.Kind)

	// Remove target pod
	m.handlePodEvent(resource.Event[*slim_corev1.Pod]{
		Kind:   resource.Delete,
		Key:    targetVMPodKey,
		Object: targetVMPod,
		Done: func(err error) {
			assert.NoError(t, err)
		},
	})
	vms = statedb.Collect(vmTable.All(db.ReadTxn()))
	require.Empty(t, vms)
}

func Test_vmReconcilerOps_Update(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
	}))
	db := statedb.New()

	sourcePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "virt-launcher-testvm-source",
			Namespace: "test-namespace",
			Labels: map[string]string{
				kubeVirtVMNameLabel:   "test-vm",
				kubeVirtNodeNameLabel: "sourcenode",
			},
			Annotations: map[string]string{
				kubeVirtAllowMigrationAnnotation: "true",
				types.DetachedAnnotation:         `{"ipv4":"10.20.30.40"}`,
			},
		},
	}
	targetPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "virt-launcher-testvm-target",
			Namespace: "test-namespace",
			Labels: map[string]string{
				kubeVirtVMNameLabel:   "test-vm",
				kubeVirtNodeNameLabel: "sourcenode",
			},
			Annotations: map[string]string{
				kubeVirtAllowMigrationAnnotation: "true",
			},
		},
	}

	sourcePodKey := resource.Key{Name: sourcePod.Name, Namespace: sourcePod.Namespace}
	targetPodKey := resource.Key{Name: targetPod.Name, Namespace: targetPod.Namespace}

	fakeClient := fake.NewClientset(sourcePod, targetPod)

	r := vmReconcilerOps{
		log:       log,
		clientset: fakeClient,
	}

	ipv4 := netip.MustParseAddr("10.20.30.40")
	vm := &KubeVirtVM{
		VMName:     sourcePodKey,
		Pods:       []resource.Key{sourcePodKey, targetPodKey},
		PrimaryPod: sourcePodKey,
		IPAM: types.DetachedIpamAddressPair{
			IPV4: &ipv4,
		},
		Status: reconciler.StatusPending(),
	}
	err := r.Update(context.TODO(), db.ReadTxn(), 0, vm)
	require.NoError(t, err)

	// Check that source pod annotation has been removed
	k8sPod, err := fakeClient.CoreV1().Pods(sourcePod.Namespace).Get(context.TODO(), sourcePod.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.NotContains(t, k8sPod.Annotations, types.DetachedAnnotation)

	// Check that target pod annotation has been added
	k8sPod, err = fakeClient.CoreV1().Pods(targetPod.Namespace).Get(context.TODO(), targetPod.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.JSONEq(t, `{"ipv4":"10.20.30.40"}`, k8sPod.Annotations[types.DetachedAnnotation])

	// Switch primary pod
	vm.PrimaryPod = targetPodKey
	err = r.Update(context.TODO(), db.ReadTxn(), 0, vm)
	require.NoError(t, err)

	// Check that source pod annotation has been added
	k8sPod, err = fakeClient.CoreV1().Pods(sourcePod.Namespace).Get(context.TODO(), sourcePod.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.JSONEq(t, `{"ipv4":"10.20.30.40"}`, k8sPod.Annotations[types.DetachedAnnotation])

	// Check that target pod annotation has been removed
	k8sPod, err = fakeClient.CoreV1().Pods(targetPod.Namespace).Get(context.TODO(), targetPod.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.NotContains(t, k8sPod.Annotations, types.DetachedAnnotation)
}
