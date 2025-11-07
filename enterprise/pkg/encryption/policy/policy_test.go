//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package policy

import (
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	networkPolicy "github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/u8proto"
)

type mockReconciler struct{}

func (m *mockReconciler) Prune() {}

type mockReconcilerMetrics struct{}

func (m *mockReconcilerMetrics) measureReconciliationTime(reason string, rev statedb.Revision) {}

func newTestEngine(t testing.TB) (
	m *Engine,
	tbl statedb.RWTable[*EncryptionPolicyEntry],
	db *statedb.DB,
) {
	hive.New(
		cell.Provide(
			NewEncryptionPolicyTable,
		),

		cell.Module(
			"encryption-policy-test",
			"encryption policy test module",

			cell.Invoke(
				func(d *statedb.DB, t statedb.RWTable[*EncryptionPolicyEntry]) {
					db = d
					tbl = t
				}),
		),
	).Populate(hivetest.Logger(t))

	logger := hivetest.Logger(t)

	m = &Engine{
		log:                 logger,
		selectorCache:       networkPolicy.NewSelectorCache(logger, identity.ListReservedIdentities()),
		db:                  db,
		policyTable:         tbl,
		reconciler:          &mockReconciler{},
		reconcilerTracker:   &mockReconcilerMetrics{},
		policyInitializer:   func(txn statedb.WriteTxn) {},
		identityInitializer: func(txn statedb.WriteTxn) {},
		metrics:             newEncryptionPolicyMetrics(),
		rulesRevision:       0,
		rulesByResource:     map[resource.Key][]*encryptionRule{},
	}

	return m, tbl, db
}

func newEvent(t *testing.T, kind resource.EventKind, name string, spec iso_v1alpha1.ClusterwideEncryptionPolicySpec) resource.Event[*iso_v1alpha1.IsovalentClusterwideEncryptionPolicy] {
	t.Helper()
	return resource.Event[*iso_v1alpha1.IsovalentClusterwideEncryptionPolicy]{
		Kind: kind,
		Key: resource.Key{
			Name: name,
		},
		Object: &iso_v1alpha1.IsovalentClusterwideEncryptionPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Spec: spec,
		},
		Done: func(err error) {
			require.NoError(t, err)
		},
	}
}

func k8sLabel(key string, value string) string {
	return "k8s:" + key + "=" + value
}

func assertEntryOwners(t *testing.T, e *EncryptionPolicyEntry, resourceNames ...string) {
	t.Helper()
	require.Len(t, e.Owners, len(resourceNames))
	for _, owner := range e.Owners {
		require.Contains(t, resourceNames, owner.Resource.String())
	}
}

func TestPolicyEngine(t *testing.T) {
	engine, tbl, db := newTestEngine(t)
	ctx := t.Context()

	fetchEntry := func(txn statedb.ReadTxn, subject, peer identity.NumericIdentity, proto u8proto.U8proto, port uint16) *EncryptionPolicyEntry {
		t.Helper()
		e, _, _ := tbl.Get(txn, EncryptionPolicyTupleIndex.Query(EncryptionTuple{
			Subject: subject,
			Peer:    peer,
			Port:    port,
			Proto:   proto,
		}))
		require.NotNil(t, e)
		return e
	}

	const testNamespace = "test-namespace"
	namespaceSelector := slim_metav1.SetAsLabelSelector(k8sLabels.Set{
		k8sConst.LabelMetadataName: testNamespace,
	})
	fooSelector := slim_metav1.SetAsLabelSelector(k8sLabels.Set{
		"foo": "1",
	})
	barSelector := slim_metav1.SetAsLabelSelector(k8sLabels.Set{
		"bar": "2",
	})
	bazSelector := slim_metav1.SetAsLabelSelector(k8sLabels.Set{
		"baz": "3",
	})

	const fooIdentity = 1001
	fooLabels := labels.NewLabelsFromModel([]string{
		k8sLabel("foo", "1"),
		k8sLabel(k8sConst.PodNamespaceLabel, testNamespace),
		k8sLabel(k8sConst.PodNamespaceMetaNameLabel, testNamespace),
	})

	const fooBarIdentity = 2001
	fooBarLabels := labels.NewLabelsFromModel([]string{
		k8sLabel("foo", "1"),
		k8sLabel("bar", "2"),
		k8sLabel(k8sConst.PodNamespaceLabel, testNamespace),
		k8sLabel(k8sConst.PodNamespaceMetaNameLabel, testNamespace),
	})

	const bazIdentity = 3001
	bazLabels := labels.NewLabelsFromModel([]string{
		k8sLabel("baz", "3"),
		k8sLabel(k8sConst.PodNamespaceLabel, testNamespace),
		k8sLabel(k8sConst.PodNamespaceMetaNameLabel, testNamespace),
	})

	const barBazIdentiy = 4001
	barBazLabels := labels.NewLabelsFromModel([]string{
		k8sLabel("bar", "2"),
		k8sLabel("baz", "3"),
		k8sLabel(k8sConst.PodNamespaceLabel, testNamespace),
		k8sLabel(k8sConst.PodNamespaceMetaNameLabel, testNamespace),
	})

	const resourceFooBar = "encrypt-foo-and-bar"
	fooBarPolicy := iso_v1alpha1.ClusterwideEncryptionPolicySpec{
		NamespaceSelector: namespaceSelector,
		PodSelector:       fooSelector,
		Peers: []iso_v1alpha1.ClusterwideEncryptionPeerSelector{
			{
				NamespaceSelector: namespaceSelector,
				PodSelector:       barSelector,
				Ports: []iso_v1alpha1.PortProtocol{
					{
						Port:     8080,
						Protocol: "TCP",
					},
				},
			},
		},
	}

	const resourceFooBarBaz = "encrypt-foo-and-bar-and-baz"
	fooBarBazPolicy := iso_v1alpha1.ClusterwideEncryptionPolicySpec{
		NamespaceSelector: namespaceSelector,
		PodSelector:       fooSelector,
		Peers: []iso_v1alpha1.ClusterwideEncryptionPeerSelector{
			{
				NamespaceSelector: namespaceSelector,
				PodSelector:       barSelector,
				Ports: []iso_v1alpha1.PortProtocol{
					{
						Port:     8080,
						Protocol: "TCP",
					},
					{
						Port:     2000,
						Protocol: "UDP",
					},
				},
			},
			{
				NamespaceSelector: namespaceSelector,
				PodSelector:       bazSelector,
				Ports: []iso_v1alpha1.PortProtocol{
					{
						Port:     8080,
						Protocol: "TCP",
					},
					{
						Port:     3000,
						Protocol: "UDP",
					},
				},
			},
		},
	}

	_, waitForStateChange := tbl.AllWatch(db.ReadTxn())
	err := engine.handleIdentityChange(ctx, IdentityChangeBatch{
		Added: identity.IdentityMap{
			fooIdentity:    fooLabels.LabelArray(),
			fooBarIdentity: fooBarLabels.LabelArray(),
			bazIdentity:    bazLabels.LabelArray(),
			barBazIdentiy:  barBazLabels.LabelArray(),
		},
	})
	require.NoError(t, err)

	// No state changes expected on empty policy list
	select {
	case <-waitForStateChange:
		t.Fatal("unexpected changes detected")
	default:
	}

	_, waitForStateChange = tbl.AllWatch(db.ReadTxn())
	err = engine.handlePolicyChange(ctx, newEvent(t, resource.Upsert, resourceFooBar, fooBarPolicy))
	require.NoError(t, err)
	<-waitForStateChange

	txn := db.ReadTxn()
	e := fetchEntry(txn, fooIdentity, fooBarIdentity, u8proto.TCP, 8080)
	assertEntryOwners(t, e, resourceFooBar)
	e = fetchEntry(txn, fooIdentity, barBazIdentiy, u8proto.TCP, 8080)
	assertEntryOwners(t, e, resourceFooBar)
	e = fetchEntry(txn, fooBarIdentity, fooBarIdentity, u8proto.TCP, 8080)
	assertEntryOwners(t, e, resourceFooBar)
	e = fetchEntry(txn, fooBarIdentity, barBazIdentiy, u8proto.TCP, 8080)
	assertEntryOwners(t, e, resourceFooBar)
	require.Equal(t, 4, tbl.NumObjects(txn))

	// Remove barBazIdentiy
	_, waitForStateChange = tbl.AllWatch(db.ReadTxn())
	err = engine.handleIdentityChange(ctx, IdentityChangeBatch{
		Deleted: identity.IdentityMap{
			barBazIdentiy: barBazLabels.LabelArray(),
		},
	})
	require.NoError(t, err)
	<-waitForStateChange

	txn = db.ReadTxn()
	e = fetchEntry(txn, fooIdentity, fooBarIdentity, u8proto.TCP, 8080)
	assertEntryOwners(t, e, resourceFooBar)
	e = fetchEntry(txn, fooBarIdentity, fooBarIdentity, u8proto.TCP, 8080)
	assertEntryOwners(t, e, resourceFooBar)
	require.Equal(t, 2, tbl.NumObjects(txn))

	// Add overlapping policy
	_, waitForStateChange = tbl.AllWatch(db.ReadTxn())

	err = engine.handlePolicyChange(ctx, newEvent(t, resource.Upsert, resourceFooBarBaz, fooBarBazPolicy))
	require.NoError(t, err)
	<-waitForStateChange

	txn = db.ReadTxn()
	// Common entries: foo -> bar [(TCP, 8000)]
	e = fetchEntry(txn, fooIdentity, fooBarIdentity, u8proto.TCP, 8080)
	assertEntryOwners(t, e, resourceFooBar, resourceFooBarBaz)
	e = fetchEntry(txn, fooBarIdentity, fooBarIdentity, u8proto.TCP, 8080)
	assertEntryOwners(t, e, resourceFooBar, resourceFooBarBaz)
	// resourceFooBarBaz entries: foo -> bar [(UDP, 2000)]
	e = fetchEntry(txn, fooIdentity, fooBarIdentity, u8proto.UDP, 2000)
	assertEntryOwners(t, e, resourceFooBarBaz)
	e = fetchEntry(txn, fooBarIdentity, fooBarIdentity, u8proto.UDP, 2000)
	assertEntryOwners(t, e, resourceFooBarBaz)
	// resourceFooBarBaz entries: foo -> baz [(TCP, 8000), (UDP, 3000)]
	e = fetchEntry(txn, fooIdentity, bazIdentity, u8proto.TCP, 8080)
	assertEntryOwners(t, e, resourceFooBarBaz)
	e = fetchEntry(txn, fooIdentity, bazIdentity, u8proto.UDP, 3000)
	assertEntryOwners(t, e, resourceFooBarBaz)
	e = fetchEntry(txn, fooBarIdentity, bazIdentity, u8proto.TCP, 8080)
	assertEntryOwners(t, e, resourceFooBarBaz)
	e = fetchEntry(txn, fooBarIdentity, bazIdentity, u8proto.UDP, 3000)
	assertEntryOwners(t, e, resourceFooBarBaz)
	require.Equal(t, 8, tbl.NumObjects(txn))

	// Remove fooBarBazPolicy
	_, waitForStateChange = tbl.AllWatch(db.ReadTxn())
	err = engine.handlePolicyChange(ctx, newEvent(t, resource.Delete, resourceFooBarBaz, fooBarBazPolicy))
	require.NoError(t, err)
	<-waitForStateChange

	txn = db.ReadTxn()
	e = fetchEntry(txn, fooIdentity, fooBarIdentity, u8proto.TCP, 8080)
	assertEntryOwners(t, e, resourceFooBar)
	e = fetchEntry(txn, fooBarIdentity, fooBarIdentity, u8proto.TCP, 8080)
	assertEntryOwners(t, e, resourceFooBar)
	require.Equal(t, 2, tbl.NumObjects(txn))

	// Modify resourceFooBar
	fooBarPolicyCopy := *fooBarPolicy.DeepCopy()
	fooBarPolicyCopy.Peers[0].Ports[0].Port = 9090
	_, waitForStateChange = tbl.AllWatch(db.ReadTxn())
	err = engine.handlePolicyChange(ctx, newEvent(t, resource.Upsert, resourceFooBar, fooBarPolicyCopy))
	require.NoError(t, err)
	<-waitForStateChange

	// Re-add barBazIdentiy
	_, waitForStateChange = tbl.AllWatch(db.ReadTxn())
	err = engine.handleIdentityChange(ctx, IdentityChangeBatch{
		Added: identity.IdentityMap{
			barBazIdentiy: barBazLabels.LabelArray(),
		},
	})
	require.NoError(t, err)
	<-waitForStateChange

	txn = db.ReadTxn()
	e = fetchEntry(txn, fooIdentity, fooBarIdentity, u8proto.TCP, 9090)
	assertEntryOwners(t, e, resourceFooBar)
	e = fetchEntry(txn, fooIdentity, barBazIdentiy, u8proto.TCP, 9090)
	assertEntryOwners(t, e, resourceFooBar)
	e = fetchEntry(txn, fooBarIdentity, fooBarIdentity, u8proto.TCP, 9090)
	assertEntryOwners(t, e, resourceFooBar)
	e = fetchEntry(txn, fooBarIdentity, barBazIdentiy, u8proto.TCP, 9090)
	assertEntryOwners(t, e, resourceFooBar)
	require.Equal(t, 4, tbl.NumObjects(txn))

	_, waitForStateChange = tbl.AllWatch(db.ReadTxn())
	err = engine.handlePolicyChange(ctx, newEvent(t, resource.Delete, resourceFooBar, fooBarPolicyCopy))
	require.NoError(t, err)
	<-waitForStateChange

	txn = db.ReadTxn()
	require.Zero(t, tbl.NumObjects(txn))
}
