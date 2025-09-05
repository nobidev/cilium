//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package relay

import (
	"context"
	"log/slog"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/tables"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/version"
)

func TestSubscribeState(t *testing.T) {
	t.Cleanup(func() { testutils.GoleakVerifyNone(t) })

	lc := hivetest.Lifecycle(t)
	log := hivetest.Logger(t)
	tempdir := t.TempDir()
	socketPath := tempdir + "/proxy-agent.sock"

	db := statedb.New()
	agentTable, _, err := tables.NewAgentStateTable(db)
	require.NoError(t, err)
	rpsTable, _, err := tables.NewRemoteProxyStateTable(db)
	require.NoError(t, err)

	s := &FQDNProxyAgentServer{
		log:            log,
		offlineEnabled: true,
		db:             db,
		agentTable:     agentTable,
		rpsTable:       rpsTable,
		socketPath:     socketPath,
	}
	s.ctx, s.cancel = context.WithCancel(t.Context())
	lc.Append(s)

	// create client
	ctx1, cancel1 := context.WithCancel(t.Context())
	tc := newTestClient(t, socketPath)
	tc.run(ctx1)

	// validate that the test client got the expected state
	as := <-tc.lastAgentState
	require.Equal(t, tables.AgentState{
		Status:            pb.AgentStatus_AS_STARTING,
		Version:           version.GetCiliumVersion().Version,
		StartTime:         startTime,
		IPCacheMapName:    ipcachemap.Name,
		EnableOfflineMode: true,
	}, tables.AgentStateFromMessage(as))

	// watch for an update to the database
	_, _, watch, found := rpsTable.GetWatch(db.ReadTxn(), tables.RemoteProxyStateIndex.Query(""))
	require.False(t, found)

	require.NoError(t, tc.stream.Send(&pb.RemoteProxyState{Status: pb.RemoteProxyStatus_RPS_LIVE}))
	<-watch
	rps, _, watch, found := rpsTable.GetWatch(db.ReadTxn(), tables.RemoteProxyStateIndex.Query(""))
	require.True(t, found)
	require.Equal(t, pb.RemoteProxyStatus_RPS_LIVE, rps.Status)

	s.setState(pb.AgentStatus_AS_LIVE)
	as = <-tc.lastAgentState
	require.Equal(t, pb.AgentStatus_AS_LIVE, as.Status)

	// See that closing the client inserts an UNSPEC
	cancel1()
	<-watch
	rps, _, found = rpsTable.Get(db.ReadTxn(), tables.RemoteProxyStateIndex.Query(""))
	require.True(t, found)
	require.Equal(t, pb.RemoteProxyStatus_RPS_UNSPECIFIED, rps.Status)

	// create new client
	ctx2, cancel2 := context.WithCancel(t.Context())
	tc = newTestClient(t, socketPath)
	tc.run(ctx2)

	t.Log("Checking that a second client receives the initial state")
	// validate that the test client got the expected state
	as = <-tc.lastAgentState
	require.Equal(t, pb.AgentStatus_AS_LIVE, as.Status)

	// simulate shutting down the agent
	t.Log("shutting down the status relay")
	require.NoError(t, s.Stop(t.Context()))

	t.Log("Checking that stopping the relay closes the server")
	// See that we got a "going away" state from the client
	as = <-tc.lastAgentState
	require.Equal(t, pb.AgentStatus_AS_UNSPECIFIED, as.Status)

	cancel2()
}

type testClient struct {
	pb.FQDNProxyAgentClient
	conn   *grpc.ClientConn
	log    *slog.Logger
	tb     testing.TB
	stream grpc.BidiStreamingClient[pb.RemoteProxyState, pb.AgentState]

	lastAgentState chan *pb.AgentState
}

func newTestClient(tb testing.TB, sockpath string) *testClient {
	tb.Helper()
	conn, err := grpc.NewClient("unix://"+sockpath,
		grpc.WithTransportCredentials(insecure.NewCredentials()))

	require.NoError(tb, err)

	tc := &testClient{
		FQDNProxyAgentClient: pb.NewFQDNProxyAgentClient(conn),
		conn:                 conn,
		tb:                   tb,
		log:                  hivetest.Logger(tb),
		lastAgentState:       make(chan *pb.AgentState, 5),
	}

	tb.Cleanup(func() { tc.conn.Close() })
	return tc
}

func (tc *testClient) run(ctx context.Context) {
	var err error
	tc.stream, err = tc.SubscribeState(ctx)
	require.NoError(tc.tb, err)

	go func() {
		var err error
		for {
			var as *pb.AgentState
			as, err = tc.stream.Recv()
			if err != nil {
				break
			}
			tc.lastAgentState <- as
			if ctx.Err() != nil {
				break
			}
		}
		tc.tb.Log("testClient was closed", err)
		tc.lastAgentState <- &pb.AgentState{}
	}()
}
