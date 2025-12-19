//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package metrics

import (
	"fmt"
	"testing"

	dto "github.com/prometheus/client_model/go"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestMetrics(t *testing.T) {
	const (
		serviceID = 1
		backendID = 2
	)

	var feAddr loadbalancer.L3n4Addr
	feAddr.ParseFromString("10.0.0.1:80/TCP")

	var beAddr loadbalancer.L3n4Addr
	beAddr.ParseFromString("10.0.0.2:8080/TCP")
	var beIPv4 types.IPv4
	beIPv4.FromAddr(beAddr.Addr())

	var (
		ctRecords = []ctmap.CtMapRecord{
			{
				Key: &ctmap.CtKey4Global{
					TupleKey4Global: tuple.TupleKey4Global{
						TupleKey4: tuple.TupleKey4{
							DestAddr:   beIPv4,
							DestPort:   8080,
							NextHeader: u8proto.TCP,
							Flags:      0,
						},
					},
				},
				Value: ctmap.CtEntry{
					Packets: 111,
					Bytes:   222,
					Flags:   0,
					RevNAT:  serviceID,
				},
			},
		}

		lmc       *lbMetricsCollector
		lbm       lbmaps.LBMaps
		ctmockMap = mockmaps.NewCtMockMap(ctRecords)
		db        *statedb.DB
		frontends statedb.RWTable[*loadbalancer.Frontend]
	)

	h := hive.New(
		cell.Group(
			cell.Provide(func() *option.DaemonConfig { return &option.DaemonConfig{} }),
			metrics.Cell,
			cell.Provide(func() loadbalancer.Config { return loadbalancer.DefaultConfig }),
			cell.Provide(func() *loadbalancer.TestConfig { return &loadbalancer.TestConfig{} }),
			cell.Provide(func() loadbalancer.ExternalConfig { return loadbalancer.ExternalConfig{EnableIPv4: true} }),
			cell.Provide(
				loadbalancer.NewFrontendsTable,
				statedb.RWTable[*loadbalancer.Frontend].ToTable,
				loadbalancer.NewBackendsTable,
				statedb.RWTable[*loadbalancer.Backend].ToTable,
				loadbalancer.NewServicesTable,
				statedb.RWTable[*loadbalancer.Service].ToTable,
			),
			maglev.Cell,
			lbmaps.Cell,
		),

		cell.Provide(
			func() Config {
				return Config{}
			},
		),
		cell.Invoke(
			func(p collectorParams, lbm_ lbmaps.LBMaps) {
				lmc = newLBMetricsCollector(p, []ctmap.CtMap{ctmockMap})
				lbm = lbm_
				db = p.DB
				frontends = p.Frontends.(statedb.RWTable[*loadbalancer.Frontend])
			},
		),
	)
	log := hivetest.Logger(t)
	require.NoError(t, h.Start(log, t.Context()))

	// Fetch metrics with no frontends
	err := lmc.fetchMetrics(t.Context())
	require.NoError(t, err, "fetchMetrics empty")

	// Insert a frontend
	wtxn := db.WriteTxn(frontends)
	serviceName := loadbalancer.NewServiceName("foo", "bar")
	frontends.Insert(wtxn,
		&loadbalancer.Frontend{
			FrontendParams: loadbalancer.FrontendParams{
				Address:     feAddr,
				ServiceName: serviceName,
			},
			ID: serviceID,
			Service: &loadbalancer.Service{
				Name: serviceName,
				Annotations: map[string]string{
					"loadbalancer.isovalent.com/type": "t1",
				},
			},
		})
	wtxn.Commit()

	// Update LBMaps
	lbm.UpdateService(
		lbmaps.NewService4Key(
			feAddr.Addr().AsSlice(),
			feAddr.Port(),
			loadbalancer.L4TypeAsProtocolNumber(feAddr.Protocol()),
			feAddr.Scope(),
			1,
		).ToNetwork(),
		&lbmaps.Service4Value{
			BackendID: backendID,
			Count:     1,
			RevNat:    serviceID,
			Flags:     0,
			Flags2:    0,
			QCount:    0,
		},
	)
	lbm.UpdateBackend(
		lbmaps.NewBackend4KeyV3(2),
		&lbmaps.Backend4ValueV3{
			Address:   beIPv4,
			Port:      8080,
			Proto:     u8proto.TCP,
			Flags:     0,
			ClusterID: 0,
			Zone:      0,
			Pad:       0,
		},
	)

	// Fetch metrics with a frontend
	err = lmc.fetchMetrics(t.Context())
	require.NoError(t, err, "fetchMetrics empty")

	ch := make(chan prometheus.Metric)
	go func() {
		lmc.Collect(ch)
		close(ch)
	}()

	for m := range ch {
		var dto dto.Metric
		m.Write(&dto)
		fmt.Printf("%v -> %v\n", m.Desc(), &dto)
	}

}
