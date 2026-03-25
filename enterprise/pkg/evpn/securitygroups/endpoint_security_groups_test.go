// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law. Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package securitygroups

import (
	"net"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	"github.com/cilium/cilium/enterprise/pkg/evpn/securitygroups/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
)

const testNodeIP = "192.0.2.10"

type fakeEndpointMetadata struct {
	id        uint16
	isPrivnet bool
}

type fakeEndpointLookup map[string]fakeEndpointMetadata

func (f fakeEndpointLookup) lookupEndpointMetadataByName(name string) (uint16, bool) {
	ep := f[name]
	return ep.id, ep.isPrivnet
}

func TestEndpointSecurityGroups(t *testing.T) {

	t.Run("match CNI source labels", func(t *testing.T) {
		const (
			endpointID             uint16 = 17
			defaultSecurityGroupID uint16 = 1
			securityGroupID        uint16 = 100
		)

		m, db, fsgs, out := newTestEndpointSecurityGroups(t, fakeEndpointLookup{
			"default/cep-a": {id: endpointID, isPrivnet: true},
		}, defaultSecurityGroupID)

		insertSecurityGroup(t, db, fsgs, securityGroupID, map[string]string{
			"cni:com.isovalent.private-network.name": "network-a",
		})

		err := m.upsertEndpoint(t.Context(), resource.Key{Namespace: "default", Name: "cep-a"}, testCEP(
			"cni:com.isovalent.private-network.name=network-a",
		))
		require.NoError(t, err)

		got, _, found := out.Get(db.ReadTxn(), tables.EndpointSecurityGroupByEndpointID(endpointID))
		require.True(t, found)
		require.Equal(t, securityGroupID, got.SecurityGroupID)
	})

	t.Run("prefer highest security group ID", func(t *testing.T) {
		const (
			endpointID             uint16 = 17
			defaultSecurityGroupID uint16 = 1
			lowerSecurityGroupID   uint16 = 100
			higherSecurityGroupID  uint16 = 200
		)

		m, db, fsgs, out := newTestEndpointSecurityGroups(t, fakeEndpointLookup{
			"default/cep-a": {id: endpointID, isPrivnet: true},
		}, defaultSecurityGroupID)

		insertSecurityGroup(t, db, fsgs, lowerSecurityGroupID, map[string]string{"app": "api"})
		insertSecurityGroup(t, db, fsgs, higherSecurityGroupID, map[string]string{"app": "api", "tier": "backend"})

		err := m.upsertEndpoint(t.Context(), resource.Key{Namespace: "default", Name: "cep-a"}, testCEP(
			"k8s:app=api",
			"k8s:tier=backend",
		))
		require.NoError(t, err)

		got, _, found := out.Get(db.ReadTxn(), tables.EndpointSecurityGroupByEndpointID(endpointID))
		require.True(t, found)
		require.Equal(t, higherSecurityGroupID, got.SecurityGroupID)

		deleteSecurityGroup(t, db, fsgs, higherSecurityGroupID)

		err = m.resyncAllEndpoints()
		require.NoError(t, err)

		got, _, found = out.Get(db.ReadTxn(), tables.EndpointSecurityGroupByEndpointID(endpointID))
		require.True(t, found)
		require.Equal(t, lowerSecurityGroupID, got.SecurityGroupID)

		deleteSecurityGroup(t, db, fsgs, lowerSecurityGroupID)

		err = m.resyncAllEndpoints()
		require.NoError(t, err)

		got, _, found = out.Get(db.ReadTxn(), tables.EndpointSecurityGroupByEndpointID(endpointID))
		require.True(t, found)
		require.Equal(t, defaultSecurityGroupID, got.SecurityGroupID)
	})

	t.Run("fall back to default security group ID", func(t *testing.T) {
		const (
			endpointID             uint16 = 17
			defaultSecurityGroupID uint16 = 1
			securityGroupID        uint16 = 100
		)

		m, db, fsgs, out := newTestEndpointSecurityGroups(t, fakeEndpointLookup{
			"default/cep-a": {id: endpointID, isPrivnet: true},
		}, defaultSecurityGroupID)

		key := resource.Key{Namespace: "default", Name: "cep-a"}

		err := m.upsertEndpoint(t.Context(), key, testCEP("k8s:app=api"))
		require.NoError(t, err)

		got, _, found := out.Get(db.ReadTxn(), tables.EndpointSecurityGroupByEndpointID(endpointID))
		require.True(t, found)
		require.Equal(t, defaultSecurityGroupID, got.SecurityGroupID)
		require.Equal(t, defaultSecurityGroupID, m.epCache[key].SecurityGroupID)

		insertSecurityGroup(t, db, fsgs, securityGroupID, map[string]string{"app": "api"})

		err = m.resyncAllEndpoints()
		require.NoError(t, err)

		got, _, found = out.Get(db.ReadTxn(), tables.EndpointSecurityGroupByEndpointID(endpointID))
		require.True(t, found)
		require.Equal(t, securityGroupID, got.SecurityGroupID)
		require.Equal(t, securityGroupID, m.epCache[key].SecurityGroupID)
	})

	t.Run("delete old mapping when endpoint ID changes", func(t *testing.T) {
		const (
			oldEndpointID          uint16 = 17
			newEndpointID          uint16 = 18
			defaultSecurityGroupID        = 1
			securityGroupID        uint16 = 100
		)

		lookup := fakeEndpointLookup{
			"default/cep-a": {id: oldEndpointID, isPrivnet: true},
		}
		m, db, fsgs, out := newTestEndpointSecurityGroups(t, lookup, defaultSecurityGroupID)

		insertSecurityGroup(t, db, fsgs, securityGroupID, map[string]string{"app": "api"})

		key := resource.Key{Namespace: "default", Name: "cep-a"}
		err := m.upsertEndpoint(t.Context(), key, testCEP("k8s:app=api"))
		require.NoError(t, err)

		lookup["default/cep-a"] = fakeEndpointMetadata{id: newEndpointID, isPrivnet: true}

		err = m.upsertEndpoint(t.Context(), key, testCEP("k8s:app=api"))
		require.NoError(t, err)

		_, _, found := out.Get(db.ReadTxn(), tables.EndpointSecurityGroupByEndpointID(oldEndpointID))
		require.False(t, found)

		got, _, found := out.Get(db.ReadTxn(), tables.EndpointSecurityGroupByEndpointID(newEndpointID))
		require.True(t, found)
		require.Equal(t, securityGroupID, got.SecurityGroupID)
		require.Equal(t, newEndpointID, m.epCache[key].EndpointID)
	})

	t.Run("skip non-privnet endpoints", func(t *testing.T) {
		const (
			endpointID             uint16 = 17
			defaultSecurityGroupID uint16 = 1
			securityGroupID        uint16 = 300
		)

		m, db, fsgs, out := newTestEndpointSecurityGroups(t, fakeEndpointLookup{
			"default/cep-a": {id: endpointID, isPrivnet: false},
		}, defaultSecurityGroupID)

		insertSecurityGroup(t, db, fsgs, securityGroupID, map[string]string{"app": "api"})

		err := m.upsertEndpoint(t.Context(), resource.Key{Namespace: "default", Name: "cep-a"}, testCEP(
			"k8s:app=api",
		))
		require.NoError(t, err)

		_, _, found := out.Get(db.ReadTxn(), tables.EndpointSecurityGroupByEndpointID(endpointID))
		require.False(t, found)
		require.Empty(t, m.epCache)
	})
}

func newTestEndpointSecurityGroups(t *testing.T, lookup fakeEndpointLookup, defaultSecurityGroupID uint16) (*endpointSecurityGroups, *statedb.DB, statedb.RWTable[tables.SecurityGroup], statedb.RWTable[tables.EndpointSecurityGroup]) {
	t.Helper()

	db := statedb.New()

	fsgs, err := tables.NewSecurityGroupsTable(db)
	require.NoError(t, err)

	out, err := tables.NewEndpointSecurityGroupTable(db)
	require.NoError(t, err)

	localNodes, err := node.NewLocalNodeTable(db)
	require.NoError(t, err)

	prevEnableIPv4 := option.Config.EnableIPv4
	option.Config.EnableIPv4 = true
	t.Cleanup(func() {
		option.Config.EnableIPv4 = prevEnableIPv4
	})

	wtx := db.WriteTxn(localNodes)
	_, _, err = localNodes.Insert(wtx, &node.LocalNode{
		Node: nodeTypes.Node{
			Name: "node-a",
			IPAddresses: []nodeTypes.Address{{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP(testNodeIP),
			}},
		},
		Local: &node.LocalNodeInfo{
			UnderlayProtocol: tunnel.IPv4,
		},
	})
	require.NoError(t, err)
	wtx.Commit()

	return &endpointSecurityGroups{
		cfg: evpnConfig.Config{
			DefaultSecurityGroupID: defaultSecurityGroupID,
		},
		db:        db,
		localNode: localNodes.ToTable(),
		sgTable:   fsgs.ToTable(),
		esgTable:  out,
		epLookup:  lookup,
		epCache:   make(map[resource.Key]endpointMapping),
	}, db, fsgs, out
}

func insertSecurityGroup(t *testing.T, db *statedb.DB, fsgs statedb.RWTable[tables.SecurityGroup], id uint16, matchLabels map[string]string) {
	t.Helper()

	wtx := db.WriteTxn(fsgs)
	_, _, err := fsgs.Insert(wtx, tables.SecurityGroup{
		GroupID: id,
		EndpointSelector: policytypes.NewLabelSelector(api.NewESFromK8sLabelSelector("", &slimv1.LabelSelector{
			MatchLabels: matchLabels,
		})),
	})
	require.NoError(t, err)
	wtx.Commit()
}

func deleteSecurityGroup(t *testing.T, db *statedb.DB, fsgs statedb.RWTable[tables.SecurityGroup], id uint16) {
	t.Helper()

	wtx := db.WriteTxn(fsgs)
	_, _, err := fsgs.Delete(wtx, tables.SecurityGroup{GroupID: id})
	require.NoError(t, err)
	wtx.Commit()
}

func testCEP(identityLabels ...string) *k8sTypes.CiliumEndpoint {
	return &k8sTypes.CiliumEndpoint{
		Networking: &ciliumv2.EndpointNetworking{
			NodeIP: testNodeIP,
		},
		Identity: &ciliumv2.EndpointIdentity{
			Labels: identityLabels,
		},
	}
}
