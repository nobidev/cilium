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
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	health "google.golang.org/grpc/health"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
	"k8s.io/utils/ptr"

	pncfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/grpc/config"
	privnettestutils "github.com/cilium/cilium/enterprise/pkg/privnet/testutils"
	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/promise"
)

type registrarOut struct {
	cell.Out

	Registrar Registrar `group:"privnet-grpc-registrars"`
}

func TestCell(t *testing.T) {
	log := hivetest.Logger(t)

	var addr atomic.Pointer[string]
	factory := func(context.Context) ([]net.Listener, error) {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		addr.Store(ptr.To(lis.Addr().String()))

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
			func() config.ServerConfigPromise {
				resolver, tlsPromise := promise.New[*certloader.WatchedServerConfig]()
				resolver.Resolve(nil)
				return config.ServerConfigPromise(tlsPromise)
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

	require.NoError(t, h.Start(log, t.Context()))
	t.Cleanup(func() {
		require.NoError(t, h.Stop(log, context.Background()))
	})

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		require.NotNil(collect, addr.Load())

		conn, err := grpc.NewClient(*addr.Load(), grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(collect, err)
		t.Cleanup(func() { _ = conn.Close() })

		resp, err := grpc_health_v1.NewHealthClient(conn).Check(t.Context(), &grpc_health_v1.HealthCheckRequest{})
		require.NoError(collect, err)
		require.Equal(collect, grpc_health_v1.HealthCheckResponse_SERVING, resp.GetStatus())
	}, 5*time.Second, 10*time.Millisecond)
}

func TestNewGRPCServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)

	paths, caPool := privnettestutils.WriteTLSFiles(t, privnettestutils.TLSConfig{
		CACommonName:   "privnet-ca",
		ServerDNSNames: []string{"cluster-a"},
		WithClientCert: true,
		ClientDNSNames: []string{"client.cluster-a"},
	})

	log := hivetest.Logger(t)
	serverTLSConfig, err := certloader.NewWatchedServerConfig(log, []string{paths.CAFile}, paths.ServerCertFile, paths.ServerKeyFile)
	require.NoError(t, err)
	t.Cleanup(serverTLSConfig.Stop)

	resolver, tlsPromise := promise.New[*certloader.WatchedServerConfig]()
	resolver.Resolve(serverTLSConfig)

	gsrv, err := newGRPCServer(ctx, config.ServerConfigPromise(tlsPromise), []Registrar{registerHealthService(t)})
	require.NoError(t, err)
	t.Cleanup(gsrv.Stop)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })

	go func() {
		_ = gsrv.Serve(lis)
	}()

	//
	// Secure client with certificate works.
	//
	clientCertificate, err := tls.LoadX509KeyPair(paths.ClientCertFile, paths.ClientKeyFile)
	require.NoError(t, err)
	conn1, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{ //nolint:gosec
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientCertificate},
		ServerName:   "cluster-a",
		MinVersion:   tls.VersionTLS13,
	})))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn1.Close() })

	resp, err := grpc_health_v1.NewHealthClient(conn1).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	require.NoError(t, err)
	require.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.GetStatus())

	//
	// Secure client without certificate fails.
	//
	conn2, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{ //nolint:gosec
		RootCAs:    caPool,
		ServerName: "cluster-a",
		MinVersion: tls.VersionTLS13,
	})))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn2.Close() })

	_, err = grpc_health_v1.NewHealthClient(conn2).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	require.Error(t, err)

	//
	// Insecure client against secure server fails.
	//
	insecureConn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = insecureConn.Close() })

	_, err = grpc_health_v1.NewHealthClient(insecureConn).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	require.Error(t, err)
}

func registerHealthService(t *testing.T) Registrar {
	t.Helper()

	srv := health.NewServer()
	srv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	return func(gsrv *grpc.Server) {
		grpc_health_v1.RegisterHealthServer(gsrv, srv)
	}
}
