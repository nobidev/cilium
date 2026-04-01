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
	"context"
	"net"
	"testing"
	"time"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	health "google.golang.org/grpc/health"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"

	pncfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
)

type registrarOut struct {
	cell.Out

	Registrar Registrar `group:"privnet-grpc-registrars"`
}

func TestCellRegistersHealthService(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)

	log := hivetest.Logger(t)

	var addr string
	factory := func(context.Context) ([]net.Listener, error) {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		addr = lis.Addr().String()
		return []net.Listener{lis}, nil
	}

	h := hive.New(
		Cell,

		cell.DecorateAll(
			func() ListenerFactory { return factory },
		),

		cell.Provide(
			func() pncfg.Config {
				return pncfg.Config{
					Enabled: true,
					Mode:    pncfg.ModeBridge,
				}
			},
			func() *health.Server {
				srv := health.NewServer()
				srv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
				return srv
			},
			func(srv *health.Server) registrarOut {
				return registrarOut{
					Registrar: func(gsrv *grpc.Server) {
						grpc_health_v1.RegisterHealthServer(gsrv, srv)
					},
				}
			},
		),
	)

	require.NoError(t, h.Start(log, ctx))
	t.Cleanup(func() { _ = h.Stop(log, context.Background()) })

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	client := grpc_health_v1.NewHealthClient(conn)
	resp, err := client.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	require.NoError(t, err)
	require.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.GetStatus())
}
