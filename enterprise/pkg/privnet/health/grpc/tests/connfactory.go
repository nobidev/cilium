//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path"

	"github.com/cilium/hive/cell"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/checker"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/time"
)

func ConnFactoryCell(path string) cell.Cell {
	return cell.Group(
		cell.Provide(
			func() ConnFactory { return ConnFactory{path: path} },
			ConnFactory.ClientConnFactory,
		),
	)
}

type ConnFactory struct {
	path string
}

func (f ConnFactory) NewListener(inst Instance) (net.Listener, error) {
	path := f.Path(Instance{Cluster: inst.Cluster, Name: inst.Name})

	err := os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("removing socket: %w", err)
	}

	lis, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listening: %w", err)
	}

	return lis, nil
}

func (f ConnFactory) ClientConnFactory() checker.ConnFactoryFn {
	return func(target tables.INBNode) (*grpc.ClientConn, error) {
		return grpc.NewClient(
			"unix://"+f.Path(Instance{Cluster: target.Cluster, Name: target.Name}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithConnectParams(grpc.ConnectParams{
				// Configure aggressive settings to make tests fast.
				MinConnectTimeout: 50 * time.Millisecond,
				Backoff: backoff.Config{
					BaseDelay:  20 * time.Millisecond,
					MaxDelay:   20 * time.Millisecond,
					Multiplier: 1,
					Jitter:     backoff.DefaultConfig.Jitter,
				},
			}),
		)
	}
}

func (f ConnFactory) Path(inst Instance) string {
	return path.Join(string(f.path), inst.SocketName())
}
