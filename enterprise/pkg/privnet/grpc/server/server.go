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
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/cilium/hive/cell"
	"google.golang.org/grpc"

	pncfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type (
	// ListenerFactory is the type of the function returning the listeners the
	// server accepts connections on.
	ListenerFactory func(ctx context.Context) ([]net.Listener, error)

	// Registrar registers a service on the shared gRPC server.
	Registrar func(*grpc.Server)
)

type server struct {
	log        *slog.Logger
	factory    ListenerFactory
	registrars []Registrar
	shutdowner hive.Shutdowner

	gsrv *grpc.Server
	wg   sync.WaitGroup
}

type serverParams struct {
	cell.In

	Logger     *slog.Logger
	Lifecycle  cell.Lifecycle
	Shutdowner hive.Shutdowner

	Config  pncfg.Config
	Factory ListenerFactory

	Registrars []Registrar `group:"privnet-grpc-registrars"`
}

func registerServer(in serverParams) {
	srv := &server{
		log:        in.Logger,
		factory:    in.Factory,
		registrars: in.Registrars,
		shutdowner: in.Shutdowner,
	}

	if !in.Config.EnabledAsBridge() || len(in.Registrars) == 0 {
		return
	}

	gsrv := grpc.NewServer(grpc.WaitForHandlers(true))
	for _, register := range in.Registrars {
		if register != nil {
			register(gsrv)
		}
	}
	srv.gsrv = gsrv

	in.Lifecycle.Append(
		cell.Hook{
			OnStart: func(hctx cell.HookContext) error {
				if srv.factory == nil {
					return fmt.Errorf("missing gRPC listener factory")
				}

				listeners, err := srv.factory(hctx)
				if err != nil {
					return fmt.Errorf("cannot create private networks gRPC listeners: %w", err)
				}

				for _, lis := range listeners {
					srv.log.Info("Starting privnet gRPC server", logfields.Address, lis.Addr().String())

					srv.wg.Go(func() {
						err := gsrv.Serve(lis)
						if err != nil {
							srv.shutdowner.Shutdown(hive.ShutdownWithError(
								fmt.Errorf("cannot start private networks gRPC server on %v: %w", lis.Addr(), err),
							))
						}
					})
				}

				return nil
			},

			OnStop: func(cell.HookContext) error {
				srv.gsrv.Stop()
				srv.wg.Wait()
				return nil
			},
		},
	)
}
