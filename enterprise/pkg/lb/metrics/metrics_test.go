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
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/byteorder"
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
)

func TestMetrics(t *testing.T) {
	const (
		serviceID  = 1
		backend1ID = 2
		backend2ID = 3
	)

	var feAddr loadbalancer.L3n4Addr
	feAddr.ParseFromString("100.64.0.1:443/TCP")
	var feIPv4 types.IPv4
	feIPv4.FromAddr(feAddr.Addr())

	var be1Addr loadbalancer.L3n4Addr
	be1Addr.ParseFromString("10.0.0.1:80/TCP")
	var be1IPv4 types.IPv4
	be1IPv4.FromAddr(be1Addr.Addr())

	var be2Addr loadbalancer.L3n4Addr
	be2Addr.ParseFromString("10.0.0.2:80/TCP")
	var be2IPv4 types.IPv4
	be2IPv4.FromAddr(be2Addr.Addr())

	var client1IPv4 types.IPv4
	clientAddr1, err := netip.ParseAddr("20.0.0.1")
	require.NoError(t, err)
	client1IPv4.FromAddr(clientAddr1)

	var client2IPv4 types.IPv4
	clientAddr2, err := netip.ParseAddr("20.0.0.2")
	require.NoError(t, err)
	client2IPv4.FromAddr(clientAddr2)

	var (
		ctRecords = []ctmap.CtMapRecord{
			{
				Key: &ctmap.CtKey4Global{
					TupleKey4Global: tuple.TupleKey4Global{
						TupleKey4: tuple.TupleKey4{
							DestAddr:   feIPv4,                                   // VIP is destination address
							SourcePort: byteorder.HostToNetwork16(feAddr.Port()), // actual dest port is in SourcePort of the CTMap, the destination is the frontend (ILB IPIP forwarding) and network byte order
							SourceAddr: client1IPv4,
							DestPort:   5553,
							NextHeader: u8proto.TCP,
							Flags:      0,
						},
					},
				},
				Value: ctmap.CtEntry{
					Packets: 100,
					Bytes:   100,
					Flags:   0,
					RevNAT:  byteorder.HostToNetwork16(serviceID),
					Union0: [2]uint64{
						0,
						backend1ID,
					},
				},
			},
			{
				Key: &ctmap.CtKey4Global{
					TupleKey4Global: tuple.TupleKey4Global{
						TupleKey4: tuple.TupleKey4{
							DestAddr:   feIPv4,                                   // VIP is destination address
							SourcePort: byteorder.HostToNetwork16(feAddr.Port()), // actual dest port is in SourcePort of the CTMap, the destination is the frontend (ILB IPIP forwarding) and network byte order
							SourceAddr: client2IPv4,
							DestPort:   5554,
							NextHeader: u8proto.TCP,
							Flags:      0,
						},
					},
				},
				Value: ctmap.CtEntry{
					Packets: 100,
					Bytes:   100,
					Flags:   0,
					RevNAT:  byteorder.HostToNetwork16(serviceID),
					Union0: [2]uint64{
						0,
						backend1ID,
					},
				},
			},
			{
				Key: &ctmap.CtKey4Global{
					TupleKey4Global: tuple.TupleKey4Global{
						TupleKey4: tuple.TupleKey4{
							DestAddr:   feIPv4,                                   // VIP is destination address
							SourcePort: byteorder.HostToNetwork16(feAddr.Port()), // actual dest port is in SourcePort of the CTMap, the destination is the frontend (ILB IPIP forwarding) and network byte order
							SourceAddr: client2IPv4,
							DestPort:   5555,
							NextHeader: u8proto.TCP,
							Flags:      0,
						},
					},
				},
				Value: ctmap.CtEntry{
					Packets: 100,
					Bytes:   100,
					Flags:   0,
					RevNAT:  byteorder.HostToNetwork16(serviceID),
					Union0: [2]uint64{
						0,
						backend2ID,
					},
				},
			},
			{
				Key: &ctmap.CtKey4Global{
					TupleKey4Global: tuple.TupleKey4Global{
						TupleKey4: tuple.TupleKey4{
							DestAddr:   feIPv4,                                   // VIP is destination address
							SourcePort: byteorder.HostToNetwork16(feAddr.Port()), // actual dest port is in SourcePort of the CTMap, the destination is the frontend (ILB IPIP forwarding) and network byte order
							SourceAddr: client1IPv4,
							DestPort:   5556,
							NextHeader: u8proto.TCP,
							Flags:      0,
						},
					},
				},
				Value: ctmap.CtEntry{
					Packets: 200,
					Bytes:   200,
					Flags:   0,
					RevNAT:  byteorder.HostToNetwork16(serviceID),
					Union0: [2]uint64{
						0,
						backend2ID,
					},
				},
			},
		}

		lmc        *lbMetricsCollector
		lbm        lbmaps.LBMaps
		ctmockMap  = mockmaps.NewCtMockMap(ctRecords)
		db         *statedb.DB
		frontends  statedb.RWTable[*loadbalancer.Frontend]
		ilbMetrics *lbMetrics
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
			cell.Provide(ctmap.NewFakeGCRunner),
			cell.Provide(newLBMetrics),
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
				ilbMetrics = p.Metrics
			},
		),
	)
	log := hivetest.Logger(t)
	require.NoError(t, h.Start(log, t.Context()))

	// Fetch metrics with no frontends
	err = lmc.fetchMetrics(t.Context())
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
			BackendID: backend1ID,
			Count:     1,
			RevNat:    serviceID,
			Flags:     0,
			Flags2:    0,
			QCount:    0,
		},
	)
	lbm.UpdateService(
		lbmaps.NewService4Key(
			feAddr.Addr().AsSlice(),
			feAddr.Port(),
			loadbalancer.L4TypeAsProtocolNumber(feAddr.Protocol()),
			feAddr.Scope(),
			2,
		).ToNetwork(),
		&lbmaps.Service4Value{
			BackendID: backend2ID,
			Count:     1,
			RevNat:    serviceID,
			Flags:     0,
			Flags2:    0,
			QCount:    0,
		},
	)
	lbm.UpdateBackend(
		lbmaps.NewBackend4KeyV3(backend1ID),
		&lbmaps.Backend4ValueV3{
			Address:   be1IPv4,
			Port:      byteorder.HostToNetwork16(be1Addr.Port()),
			Proto:     u8proto.TCP,
			Flags:     0,
			ClusterID: 0,
			Zone:      0,
			Pad:       0,
		},
	)
	lbm.UpdateBackend(
		lbmaps.NewBackend4KeyV3(backend2ID),
		&lbmaps.Backend4ValueV3{
			Address:   be2IPv4,
			Port:      byteorder.HostToNetwork16(be2Addr.Port()),
			Proto:     u8proto.TCP,
			Flags:     0,
			ClusterID: 0,
			Zone:      0,
			Pad:       0,
		},
	)

	// Fetch metrics with a frontend
	err = lmc.fetchMetrics(t.Context())
	require.NoError(t, err)

	require.Len(t, ctmockMap.Entries, 4)
	require.Len(t, lmc.prevLbCtEntries, 4)

	assertServiceBackendMetric(t, ilbMetrics, "foo_bar", "10.0.0.1:80/TCP", 200.0, 200.0, 2, 1)
	assertServiceBackendMetric(t, ilbMetrics, "foo_bar", "10.0.0.2:80/TCP", 300.0, 300.0, 2, 1)

	ctRecords[0].Value.Packets = 10000 // modify one CTmap entry for service foobar - backend 1
	ctRecords[1].Value.Bytes = 30000   // modify one CTmap entry for service foobar - backend 1

	err = lmc.fetchMetrics(t.Context())
	require.NoError(t, err)

	assertServiceBackendMetric(t, ilbMetrics, "foo_bar", "10.0.0.1:80/TCP", 10100.0, 30100.0, 2, 1)
	assertServiceBackendMetric(t, ilbMetrics, "foo_bar", "10.0.0.2:80/TCP", 300.0, 300.0, 2, 1)

	ctRecords[2].Value.Packets = 500 // modify one CTmap entry for service foobar - backend 2
	ctRecords[2].Value.Bytes = 1000  // modify one CTmap entry for service foobar - backend 2

	err = lmc.fetchMetrics(t.Context())
	require.NoError(t, err)

	assertServiceBackendMetric(t, ilbMetrics, "foo_bar", "10.0.0.1:80/TCP", 10100.0, 30100.0, 2, 1)
	assertServiceBackendMetric(t, ilbMetrics, "foo_bar", "10.0.0.2:80/TCP", 700.0, 1200.0, 2, 1)

	// Delete one ctmap entry and trigger GC event handling

	ctmockMap.Entries = ctmockMap.Entries[1:]

	require.Len(t, ctmockMap.Entries, 3)

	lmc.handleCTGCEvent(t.Context(), ctmap.GCEvent{
		Key: &ctmap.CtKey4Global{
			TupleKey4Global: tuple.TupleKey4Global{
				TupleKey4: tuple.TupleKey4{
					DestAddr:   feIPv4,                                   // VIP is destination address
					SourcePort: byteorder.HostToNetwork16(feAddr.Port()), // actual dest port is in SourcePort of the CTMap, the destination is the frontend (ILB IPIP forwarding) and network byte order
					SourceAddr: client1IPv4,
					DestPort:   5553,
					NextHeader: u8proto.TCP,
					Flags:      0,
				},
			},
		},
	})
	require.Len(t, lmc.prevLbCtEntries, 3, "CTGCEvent needs to cleanup prevLbCtEntries map")

	err = lmc.fetchMetrics(t.Context())
	require.NoError(t, err)

	assertServiceBackendMetric(t, ilbMetrics, "foo_bar", "10.0.0.1:80/TCP", 10100.0, 30100.0, 1, 1)
	assertServiceBackendMetric(t, ilbMetrics, "foo_bar", "10.0.0.2:80/TCP", 700.0, 1200.0, 2, 1)

	// Delete next ctmap entry for service & backend

	ctmockMap.Entries = ctmockMap.Entries[1:]

	lmc.handleCTGCEvent(t.Context(), ctmap.GCEvent{
		Key: &ctmap.CtKey4Global{
			TupleKey4Global: tuple.TupleKey4Global{
				TupleKey4: tuple.TupleKey4{
					DestAddr:   feIPv4,                                   // VIP is destination address
					SourcePort: byteorder.HostToNetwork16(feAddr.Port()), // actual dest port is in SourcePort of the CTMap, the destination is the frontend (ILB IPIP forwarding) and network byte order
					SourceAddr: client2IPv4,
					DestPort:   5554,
					NextHeader: u8proto.TCP,
					Flags:      0,
				},
			},
		},
	})

	err = lmc.fetchMetrics(t.Context())
	require.NoError(t, err)

	// removal of CTMap entries doesn't affect the total packets and bytes for a service and backend
	assertServiceBackendMetric(t, ilbMetrics, "foo_bar", "10.0.0.1:80/TCP", 10100.0, 30100.0, 0, 1)
	assertServiceBackendMetric(t, ilbMetrics, "foo_bar", "10.0.0.2:80/TCP", 700.0, 1200.0, 2, 1)

	// remove backend (and fetch until metrics entry is EOL)
	err = lbm.DeleteBackend(lbmaps.NewBackend4KeyV3(backend1ID))
	require.NoError(t, err)

	for range entryTimeToLive + 1 {
		err = lmc.fetchMetrics(t.Context())
		require.NoError(t, err)
	}

	// removal of backend cleans the metrics
	assertServiceBackendMetric(t, ilbMetrics, "foo_bar", "10.0.0.1:80/TCP", 0, 0, 0, 0) // actually deleted
	assertServiceBackendMetric(t, ilbMetrics, "foo_bar", "10.0.0.2:80/TCP", 700.0, 1200.0, 2, 1)
}

func assertServiceBackendMetric(t *testing.T, metrics *lbMetrics, service string, backend string, expectedPackets float64, expectedBytes float64, expectedConns float64, expectedHealth float64) {
	actualPackets, err := metrics.LBPackets.GetMetricWithLabelValues(service, backend)
	require.NoError(t, err)
	require.Equal(t, expectedPackets, actualPackets.Get())

	actualBytes, err := metrics.LBBytes.GetMetricWithLabelValues(service, backend)
	require.NoError(t, err)
	require.Equal(t, expectedBytes, actualBytes.Get())

	actualConns, err := metrics.LBOpenConnections.GetMetricWithLabelValues(service, backend)
	require.NoError(t, err)
	require.Equal(t, expectedConns, actualConns.Get())

	actualHealth, err := metrics.LBHealthCheckStatus.GetMetricWithLabelValues(service, backend)
	require.NoError(t, err)
	require.Equal(t, expectedHealth, actualHealth.Get())
}
