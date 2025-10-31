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
	"net"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/checker"
	"github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/server"
	ht "github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/tests"
	"github.com/cilium/cilium/enterprise/pkg/privnet/reconcilers"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
)

func Health(path string) cell.Cell {
	return cell.Group(
		ht.ConnFactoryCell(path),
		ht.ServerPoolCell,
		ht.CheckerPoolCell,

		cell.DecorateAll(
			func(factory ht.ConnFactory) checker.ConnFactoryFn { return factory.ClientConnFactory() },
		),

		cell.DecorateAll(
			func(cf ht.ConnFactory, cinfo cmtypes.ClusterInfo) server.ListenerFactory {
				return func() (net.Listener, error) {
					return cf.NewListener(ht.Instance{
						Cluster: tables.ClusterName(cinfo.Name), Name: nodeName})
				}
			},
		),

		cell.DecorateAll(
			// Ensure consistent selection of the active INB by always picking the
			// one associated with the smallest IP address.
			func() reconcilers.ActiveINBIndexFunc {
				return func(candidates []tables.INB) (out int) {
					for idx := range candidates {
						if candidates[idx].Node.IP.Less(candidates[out].Node.IP) {
							out = idx
						}
					}

					return out
				}
			},
		),
	)
}
