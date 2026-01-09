//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package remoteproxy

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	dnsproxypb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	fqdnhaconfig "github.com/cilium/cilium/enterprise/pkg/fqdnha/config"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/doubleproxy"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/tables"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"
)

type mockFQDNProxyClient struct {
	allowed map[string]*dnsproxypb.L7Rules
}

func newMockFQDNProxyClient() *mockFQDNProxyClient {
	return &mockFQDNProxyClient{
		allowed: map[string]*dnsproxypb.L7Rules{},
	}
}

func (m *mockFQDNProxyClient) UpdateAllowed(
	ctx context.Context,
	in *dnsproxypb.FQDNRules,
	opts ...grpc.CallOption,
) (*dnsproxypb.Empty, error) {
	k := fmt.Sprintf("%d:%d:%d", in.EndpointID, in.DestProto, in.DestPort)
	if in.Rules == nil {
		delete(m.allowed, k)
	} else {
		m.allowed[k] = in.Rules
	}
	return nil, nil
}

func (m *mockFQDNProxyClient) RemoveRestoredRules(
	ctx context.Context,
	in *dnsproxypb.EndpointID,
	opts ...grpc.CallOption,
) (*dnsproxypb.Empty, error) {
	return nil, nil
}

func (m *mockFQDNProxyClient) GetRules(
	ctx context.Context,
	in *dnsproxypb.EndpointID,
	opts ...grpc.CallOption,
) (*dnsproxypb.RestoredRules, error) {
	return nil, nil
}

type mockDoubleProxy struct{}

func (m *mockDoubleProxy) RegisterRemote() *doubleproxy.AckTracker {
	return doubleproxy.NewAckTracker()
}

func (m *mockDoubleProxy) UnregisterRemote(at *doubleproxy.AckTracker) {}

// Test that a client that connects never misses a single update, even if it disconnects and reconnects.
//
// This also ensures that we dump and load our state correctly, as we only intercept proxy updates
// after agent restarts.
func TestConnectionLifecycle(t *testing.T) {
	cfg := fqdnhaconfig.Config{EnableExternalDNSProxy: true}
	db := statedb.New()
	require.NoError(t, db.Start())
	// Make sure no goroutines leak
	t.Cleanup(func() {
		db.Stop()
		testutils.GoleakVerifyNone(t)
	})

	tbl, _, err := tables.NewProxyConfigTable(cfg, db)
	require.NoError(t, err)

	remoteProxy := RemoteFQDNProxy{
		log:         slog.Default(),
		db:          db,
		configTable: tbl,
		dp:          &mockDoubleProxy{},
	}

	allowExampleCom := policy.L7DataMap{
		mockCachedSelector("selector"): &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{{
					MatchName: "example.com",
				}},
			},
		},
	}

	addRule := func(epID uint64, port uint16) {
		t.Helper()
		wtx := db.WriteTxn(tbl)
		defer wtx.Abort()
		_, _, err := tbl.Insert(wtx, tables.NewProxyConfig(epID, restore.MakeV2PortProto(port, u8proto.UDP), allowExampleCom))
		require.NoError(t, err)
		wtx.Commit()
	}

	addRule(1, 35)
	addRule(2, 35)
	addRule(1, 35) // overwrites
	addRule(2, 36)

	require.Equal(t, 3, tbl.NumObjects(db.ReadTxn()))

	remoteContext, remoteCancel := context.WithCancel(t.Context())

	// Initialize the remote proxy
	mock := newMockFQDNProxyClient()
	// and consume updates as they come
	go remoteProxy.forwardUpdates(remoteContext, mock)

	// Ensure the remote proxy has all already-existing rules.
	// Note that updates are queued and applied asynchronously, so we must wait
	require.Eventually(t, func() bool {
		return len(mock.allowed) == 3
	}, time.Second, 10*time.Millisecond)

	// Add another rule
	addRule(4, 35)
	require.Eventually(t, func() bool {
		return len(mock.allowed) == 4
	}, time.Second, 10*time.Millisecond)

	addRule(5, 35)
	require.Eventually(t, func() bool {
		return len(mock.allowed) == 5
	}, time.Second, 10*time.Millisecond)

	// Disconnect, ensure that we do not block
	remoteCancel()

	addRule(6, 35)
	require.Equal(t, 6, tbl.NumObjects(db.ReadTxn()))

	addRule(7, 35)
	require.Equal(t, 7, tbl.NumObjects(db.ReadTxn()))

}

type mockCachedSelector string

func (m mockCachedSelector) GetSelections() identity.NumericIdentitySlice {
	return []identity.NumericIdentity{1, 2, 3}
}
func (m mockCachedSelector) GetSelectionsAt(_ policy.SelectorSnapshot) identity.NumericIdentitySlice {
	return []identity.NumericIdentity{1, 2, 3}
}
func (m mockCachedSelector) GetMetadataLabels() labels.LabelArray { panic("not impl") }
func (m mockCachedSelector) Selects(_ identity.NumericIdentity) bool {
	panic("not impl")
}
func (m mockCachedSelector) IsWildcard() bool { panic("not impl") }
func (m mockCachedSelector) IsNone() bool     { panic("not impl") }
func (m mockCachedSelector) String() string   { return string(m) }
