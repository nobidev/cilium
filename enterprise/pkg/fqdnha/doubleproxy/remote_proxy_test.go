//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package doubleproxy

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	fqdnhaconfig "github.com/cilium/cilium/enterprise/pkg/fqdnha/config"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/tables"
	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointstate"
	fqdnproxy "github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"
)

var _ fqdnproxy.DNSProxier = (*mockDNSProxy)(nil)

type mockDNSProxy struct {
	listened chan struct{}
}

func makeMockProxy() *mockDNSProxy {
	return &mockDNSProxy{
		listened: make(chan struct{}),
	}
}

func (m *mockDNSProxy) Listen(uint16) error {
	close(m.listened)
	return nil
}

type mockRestorer struct {
	done chan struct{}
}

func makeMockRestorer() *mockRestorer {
	return &mockRestorer{
		done: make(chan struct{}),
	}
}

func (r *mockRestorer) Await(context.Context) (endpointstate.Restorer, error) {
	return r, nil
}

func (r *mockRestorer) WaitForEndpointRestoreWithoutRegeneration(ctx context.Context) error {
	return nil
}

func (r *mockRestorer) WaitForEndpointRestore(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.done:
		return nil
	}
}

func (r *mockRestorer) WaitForInitialPolicy(_ context.Context) error {
	return nil
}

func setup(t *testing.T) *DoubleProxy {
	db := statedb.New()
	rpsTable, _, err := tables.NewRemoteProxyStateTable(db)
	require.NoError(t, err)

	cfg := fqdnhaconfig.Config{
		EnableOfflineMode:      true,
		EnableExternalDNSProxy: true,
	}

	dp := NewDoubleProxy(Params{
		Cfg:                   cfg,
		Log:                   hivetest.Logger(t),
		DB:                    db,
		RemoteProxyStateTable: rpsTable,
		RestorerPromise:       makeMockRestorer(),
	})
	dp.ctx = t.Context()

	return dp
}

func setStatus(t *testing.T, dp *DoubleProxy, status pb.RemoteProxyStatus) {
	t.Helper()
	wtx := dp.db.WriteTxn(dp.rpsTable)
	defer wtx.Abort()

	state := tables.RemoteProxyState{
		Status:            status,
		EnableOfflineMode: true,
	}
	_, _, err := dp.rpsTable.Insert(wtx, state)
	require.NoError(t, err)
	wtx.Commit()
}

func TestListenProxyCrashed(t *testing.T) {
	t.Parallel()
	dp := setup(t)

	mockProxy := makeMockProxy()

	pw := DecorateDNSProxy(dp, mockProxy).(*proxyWrapper)
	require.NotNil(t, pw)

	pw.Listen(1234)
	// proxy goes up and down
	setStatus(t, dp, pb.RemoteProxyStatus_RPS_REPLAYING)
	setStatus(t, dp, pb.RemoteProxyStatus_RPS_UNSPECIFIED)

	// channel should close almost immediately
	// still need some small delay since it's not synchronous
	select {
	case <-time.After(500 * time.Millisecond):
		t.Fatal("didn't listen after 3 seconds")
	case <-mockProxy.listened:
	}
}

func TestListenRestoreDone(t *testing.T) {
	t.Parallel()
	dp := setup(t)

	mockProxy := makeMockProxy()

	pw := DecorateDNSProxy(dp, mockProxy).(*proxyWrapper)
	require.NotNil(t, pw)

	pw.Listen(1234)
	setStatus(t, dp, pb.RemoteProxyStatus_RPS_REPLAYING)

	close(dp.restorerPromise.(*mockRestorer).done)

	// channel should close almost immediately
	// still need some small delay since it's not synchronous
	select {
	case <-time.After(500 * time.Millisecond):
		t.Fatal("didn't listen after 3 seconds")
	case <-mockProxy.listened:
	}
}

// boilerplate
func (m *mockDNSProxy) GetRules(*versioned.VersionHandle, uint16) (restore.DNSRules, error) {
	return nil, nil
}

func (m *mockDNSProxy) RemoveRestoredRules(u uint16) {
}

func (m *mockDNSProxy) UpdateAllowed(endpointID uint64, destPort restore.PortProto, newRules policy.L7DataMap) (revert.RevertFunc, error) {
	return nil, nil
}

func (m *mockDNSProxy) GetBindPort() uint16 {
	return 0
}

func (m *mockDNSProxy) RestoreRules(op *endpoint.Endpoint) {
}

func (m *mockDNSProxy) Cleanup() {
}
