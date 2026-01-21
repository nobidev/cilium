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
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/observers"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

var Cell = cell.Group(
	config.Cell,

	// Endpoints
	cell.Group(
		cell.Provide(
			observers.NewPrivateNetworkEndpoints,
			tables.NewEndpointsTable,
		),

		cell.Invoke(
			registerEndpointsReflector,
		),
	),
)

func registerEndpointsReflector(cfg config.Config, jg job.Group, db *statedb.DB,
	tbl statedb.RWTable[tables.Endpoint], obs *observers.PrivateNetworkEndpoints) {
	if !cfg.Enabled {
		return
	}

	wtx := db.WriteTxn(tbl)
	init := tbl.RegisterInitializer(wtx, "clustermesh")
	wtx.Commit()

	jg.Add(
		job.Observer(
			"clustermesh-privnet-endpoints-to-table",
			func(ctx context.Context, buf observers.EndpointEvents) error {
				wtx := db.WriteTxn(tbl)

				for _, ev := range buf {
					switch ev.EventKind {
					case resource.Upsert:
						// We should also take care of deleting possible stale entries
						// (see the comment of [Endpoints.registerClusterMeshReflector]),
						// but a simpler version is more than enough for testing purposes.
						tbl.Insert(wtx, tables.Endpoint{Endpoint: ev.Object})
					case resource.Delete:
						tbl.Delete(wtx, tables.Endpoint{Endpoint: ev.Object})
					case resource.Sync:
						init(wtx)
					}
				}

				wtx.Commit()
				return nil
			}, obs,
		),
	)
}
