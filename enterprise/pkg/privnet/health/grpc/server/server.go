//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package server

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pncfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	api "github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/api/v1"
	"github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

type (
	// ListenerFactory is the type of the function returning the listener the
	// server accepts connections on.
	ListenerFactory func() (net.Listener, error)
)

func newDefaultListenerFactory(cfg config.Config) ListenerFactory {
	port := strconv.FormatUint(uint64(cfg.Port), 10)
	return func() (net.Listener, error) {
		// Currently, we listen to all addresses for simplicity, even though suboptimal.
		return net.Listen("tcp", net.JoinHostPort("", port))
	}
}

type server struct {
	api.UnimplementedHealthServer
	api.UnimplementedNetworksServer

	log *slog.Logger

	db       *statedb.DB
	networks statedb.Table[tables.PrivateNetwork]
	tbl      statedb.RWTable[tables.ActiveNetwork]

	// hmu protects the access to [healthy]. It must be always acquired first
	// when acquiring a write transaction as well.
	hmu     lock.RWMutex
	healthy map[tables.WorkloadNode]wnEntry

	wg   sync.WaitGroup
	stop chan struct{}
}

type wnEntry struct {
	timeout *time.Timer
}

type serverParams struct {
	cell.In

	Logger     *slog.Logger
	Lifecycle  cell.Lifecycle
	Shutdowner hive.Shutdowner

	Config  pncfg.Config
	Factory ListenerFactory

	DB       *statedb.DB
	Networks statedb.Table[tables.PrivateNetwork]
	Table    statedb.RWTable[tables.ActiveNetwork]
}

func newServer(in serverParams) *server {
	srv := &server{
		log: in.Logger,

		db:       in.DB,
		networks: in.Networks,
		tbl:      in.Table,

		healthy: make(map[tables.WorkloadNode]wnEntry),
		stop:    make(chan struct{}),
	}

	// The health server is only started when we are running in bridge mode.
	if !in.Config.EnabledAsBridge() {
		return srv
	}

	gsrv := grpc.NewServer(grpc.WaitForHandlers(true))
	api.RegisterHealthServer(gsrv, srv)
	api.RegisterNetworksServer(gsrv, srv)

	in.Lifecycle.Append(
		cell.Hook{
			OnStart: func(cell.HookContext) error {
				lis, err := in.Factory()
				if err != nil {
					return fmt.Errorf("cannot create private networks health server listener: %w", err)
				}

				srv.wg.Go(func() {
					err := gsrv.Serve(lis)
					if err != nil {
						in.Shutdowner.Shutdown(hive.ShutdownWithError(
							fmt.Errorf("cannot start private networks health server: %w", err),
						))
					}
				})

				return nil
			},

			OnStop: func(cell.HookContext) error {
				close(srv.stop)
				gsrv.Stop()
				srv.wg.Wait()
				return nil
			},
		},
	)

	return srv
}

func (s *server) Probe(stream grpc.BidiStreamingServer[api.ProbeRequest, api.ProbeResponse]) error {
	var known tables.WorkloadNode

	for {
		request, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("receiving: %w", err)
		}

		node, err := s.toWorkloadNode(request.GetSelf())
		if err != nil {
			return err
		}

		if known == (tables.WorkloadNode{}) {
			// We received the first message from the stream. Let's make sure that
			// all subsequent ones include the same node information.
			known = node
		} else if node != known {
			return status.Error(codes.InvalidArgument, "mismatching [Self] parameter")
		}

		timeout := request.GetTimeout().AsDuration()
		if timeout == 0 {
			return status.Error(codes.InvalidArgument, "invalid [Timeout] parameter")
		}

		s.onProbe(node, timeout)

		err = stream.Send(&api.ProbeResponse{Status: api.ProbeResponse_SERVING})
		if err != nil {
			return fmt.Errorf("sending: %w", err)
		}
	}
}

func (s *server) onProbe(node tables.WorkloadNode, timeout time.Duration) {
	s.hmu.Lock()
	defer s.hmu.Unlock()

	entry, found := s.healthy[node]
	if found {
		// The node was already healthy: restart the timeout timer.
		entry.timeout.Reset(timeout)
		return
	}

	// The node just became healthy: start the timeout logic.
	entry = wnEntry{
		timeout: time.NewTimer(timeout),
	}

	s.wg.Go(func() {
		select {
		case <-s.stop:
		case <-entry.timeout.C:
			s.onProbeTimeout(node)
		}
	})

	s.healthy[node] = entry
	s.log.Info("Registered new healthy workload node", logfields.Node, node)
}

func (s *server) onProbeTimeout(node tables.WorkloadNode) {
	s.hmu.Lock()
	defer s.hmu.Unlock()

	s.log.Info("Workload node is no longer healthy", logfields.Node, node)
	delete(s.healthy, node)

	wtx := s.db.WriteTxn(s.tbl)

	// The node is no longer considered healthy, hence drop all active networks.
	for active := range s.tbl.Prefix(wtx, tables.ActiveNetworkByNode(node)) {
		s.tbl.Delete(wtx, active)
	}

	wtx.Commit()
}

func (s *server) toWorkloadNode(in *api.Node) (tables.WorkloadNode, error) {
	out := tables.WorkloadNode{
		Cluster: tables.ClusterName(in.GetCluster()),
		Name:    tables.NodeName(in.GetName()),
	}

	if out.Cluster == "" || out.Name == "" {
		return tables.WorkloadNode{}, status.Error(codes.InvalidArgument, "invalid [Self] parameter")
	}

	return out, nil
}
