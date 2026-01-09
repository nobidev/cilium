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
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/statedb"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/tuple"
)

// lbMetricsCollector implements Prometheus Collector interface and store the state of the metrics collector
type lbMetricsCollector struct {
	db                      *statedb.DB
	frontends               statedb.Table[*loadbalancer.Frontend]
	lbmaps                  lbmaps.LBMaps
	logger                  *slog.Logger
	ct4Maps                 []ctmap.CtMap
	lbBytesDesc             *prometheus.Desc
	lbPacketsDesc           *prometheus.Desc
	lbOpenConnectionsDesc   *prometheus.Desc
	lbHealthcheckStatusDesc *prometheus.Desc

	// Mutex protects the fields below
	lock.Mutex

	// round number is monotonically increasing.
	// Used to detect orphaned backend metrics.
	round uint64

	// prevLbCtEntries stores a snapshot of the LB CT entries
	prevLbCtEntries map[tuple.TupleKey4]*ctmap.CtEntry

	// backendMetrics stores metrics (bytes, packets, health) for each backend
	backendMetrics map[backendMetricKey]*backendMetricValue

	// lbOpenConnections is a counter for the number of open connections
	lbOpenConnections int
}

type backendMetricKey struct {
	name loadbalancer.ServiceName
	addr loadbalancer.L3n4Addr
}

type backendMetricValue struct {
	updatedAt uint64
	bytes     uint64
	packets   uint64
	healthy   bool
}

// entryTimeToLive is how many [fetchMetrics] rounds a [backendMetricValue]
// stays around even when the associated CT entry is gone.
const entryTimeToLive = 10

func newLBMetricsCollector(params collectorParams, ct4Maps []ctmap.CtMap) *lbMetricsCollector {
	return &lbMetricsCollector{
		db:        params.DB,
		frontends: params.Frontends,

		prevLbCtEntries: make(map[tuple.TupleKey4]*ctmap.CtEntry),
		backendMetrics:  make(map[backendMetricKey]*backendMetricValue),

		ct4Maps: ct4Maps,

		lbBytesDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, "", "lb_bytes_total"),
			"Total received bytes, tagged by LB service and backend",
			[]string{"service", "backend"}, nil,
		),
		lbPacketsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, "", "lb_packets_total"),
			"Total received packets, tagged by LB service and backend",
			[]string{"service", "backend"}, nil,
		),
		lbOpenConnectionsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, "", "lb_open_connections_metric"),
			"Number of open LB connections",
			[]string{}, nil,
		),
		lbHealthcheckStatusDesc: prometheus.NewDesc(
			prometheus.BuildFQName(metrics.Namespace, "", "lb_healthcheck_status"),
			"Healthcheck status for a given service and backend tuple",
			[]string{"service", "backend"}, nil,
		),

		lbmaps: params.LBMaps,

		logger: params.Logger,
	}
}

func (mc *lbMetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- mc.lbBytesDesc
	ch <- mc.lbPacketsDesc
	ch <- mc.lbOpenConnectionsDesc
	ch <- mc.lbHealthcheckStatusDesc
}

func (mc *lbMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	mc.Lock()
	defer mc.Unlock()

	nameAsLabelValue := func(n loadbalancer.ServiceName) string {
		return n.Namespace() + "_" + n.Name()
	}

	ch <- prometheus.MustNewConstMetric(mc.lbOpenConnectionsDesc, prometheus.GaugeValue, float64(mc.lbOpenConnections))
	for key, entry := range mc.backendMetrics {
		serviceName := nameAsLabelValue(key.name)
		backend := key.addr.StringWithProtocol()
		ch <- prometheus.MustNewConstMetric(mc.lbBytesDesc, prometheus.CounterValue, float64(entry.bytes), serviceName, backend)
		ch <- prometheus.MustNewConstMetric(mc.lbPacketsDesc, prometheus.CounterValue, float64(entry.packets), serviceName, backend)
		s := 0
		if entry.healthy {
			s = 1
		}
		ch <- prometheus.MustNewConstMetric(mc.lbHealthcheckStatusDesc, prometheus.GaugeValue, float64(s), serviceName, backend)
	}
}

func (mc *lbMetricsCollector) fetchMetrics(ctx context.Context) error {
	// Skip collection if frontends are not initialized yet
	if init, _ := mc.frontends.Initialized(mc.db.ReadTxn()); !init {
		return nil
	}

	mc.Lock()
	defer mc.Unlock()

	mc.round++
	mc.lbOpenConnections = 0

	// Iterate the backend map to collect a list of all backends
	backends, err := mc.getBackends()
	if err != nil {
		return fmt.Errorf("failed to get backends: %w", err)
	}

	// Iterate the service map to collect the health status of all LB services
	if err := mc.updateMetricsEntryWithServiceHealth(backends); err != nil {
		return fmt.Errorf("failed to update metrics entry with service health: %w", err)
	}

	// calculate the deltas between the current CT entry's counters and the previous one's (if it exists)
	if err := mc.updateMetricsEntryWithCTMapInfo(backends); err != nil {
		return fmt.Errorf("failed to update metrics entry with CT map info: %w", err)
	}

	// Drop metrics for backends that have not had an associated CT entry
	// for [entryTimeToLive] collection rounds.
	for key, entry := range mc.backendMetrics {
		if entry.updatedAt+entryTimeToLive < mc.round {
			delete(mc.backendMetrics, key)
		}
	}

	return nil
}

func (mc *lbMetricsCollector) getBackends() (map[loadbalancer.BackendID]*lbmaps.Backend4ValueV3, error) {
	backends := map[loadbalancer.BackendID]*lbmaps.Backend4ValueV3{}

	backendsCallback := func(key lbmaps.BackendKey, value lbmaps.BackendValue) {
		backendKey, ok := key.(*lbmaps.Backend4KeyV3)
		if !ok {
			return
		}
		backendVal, ok := value.(*lbmaps.Backend4ValueV3)
		if !ok {
			return
		}
		backendVal = backendVal.ToHost().(*lbmaps.Backend4ValueV3)

		backends[backendKey.ID] = backendVal
	}

	if err := mc.lbmaps.DumpBackend(backendsCallback); err != nil {
		mc.logger.Error("Cannot dump backend map, LB metrics may be incomplete", logfields.Error, err)
		return nil, err
	}

	return backends, nil
}

func (mc *lbMetricsCollector) updateMetricsEntryWithServiceHealth(backends map[loadbalancer.BackendID]*lbmaps.Backend4ValueV3) error {
	serviceCallback := func(key lbmaps.ServiceKey, value lbmaps.ServiceValue) {
		serviceKey, ok := key.(*lbmaps.Service4Key)
		if !ok {
			return
		}
		serviceKey = serviceKey.ToHost().(*lbmaps.Service4Key)
		serviceVal, ok := value.(*lbmaps.Service4Value)
		if !ok {
			return
		}

		svcName, _, isT1 := mc.getService(svcKeyToAddr(serviceKey))
		if !isT1 {
			return
		}

		// lookup the service's backend from the cache
		serviceBackend, ok := backends[loadbalancer.BackendID(serviceVal.BackendID)]
		if !ok {
			return
		}

		backendAddr := beValueToAddr(serviceBackend)

		// and update the health status of the service's backend
		mc.getOrAddEntry(svcName, backendAddr).healthy = serviceVal.GetFlags() == 0
	}
	if err := mc.lbmaps.DumpService(serviceCallback); err != nil {
		mc.logger.Error("Cannot dump service map, LB metrics may be incomplete", logfields.Error, err)
		return err
	}

	return nil
}

func (mc *lbMetricsCollector) updateMetricsEntryWithCTMapInfo(backends map[loadbalancer.BackendID]*lbmaps.Backend4ValueV3) error {
	ctMapCallback := func(key bpf.MapKey, value bpf.MapValue) {
		ctKey := key.(*ctmap.CtKey4Global).ToHost().(*ctmap.CtKey4Global)
		ctValue := value.(*ctmap.CtEntry)

		svcName, svcID, isT1 := mc.getService(ctKeyToAddr(ctKey))
		if !isT1 {
			return
		}

		if ctValue.RevNAT != uint16(svcID) {
			return
		}

		// lookup the CT entry's backend from the cache
		backend, ok := backends[loadbalancer.BackendID(ctValue.Union0[1])]
		if !ok {
			return
		}

		// calculate the deltas between the current CT entry's counters and the previous one's (if it exists)
		deltaBytes := ctValue.Bytes
		deltaPackets := ctValue.Packets
		if prevCtValue, ok := mc.prevLbCtEntries[ctKey.TupleKey4]; ok {
			deltaBytes -= prevCtValue.Bytes
			deltaPackets -= prevCtValue.Packets
		}
		mc.prevLbCtEntries[ctKey.TupleKey4] = ctValue

		backendAddr := beValueToAddr(backend)
		entry := mc.getOrAddEntry(svcName, backendAddr)
		entry.bytes += deltaBytes
		entry.packets += deltaPackets

		mc.lbOpenConnections++
	}

	for _, ctMap := range mc.ct4Maps {
		if err := ctMap.DumpWithCallback(ctMapCallback); err != nil {
			mc.logger.Error("Cannot dump CT map, LB metrics may be incomplete", logfields.Error, err)
			return err
		}
	}

	return nil
}

func (mc *lbMetricsCollector) getService(addr loadbalancer.L3n4Addr) (loadbalancer.ServiceName, loadbalancer.ServiceID, bool) {
	txn := mc.db.ReadTxn()
	fe, _, found := mc.frontends.Get(txn, loadbalancer.FrontendByAddress(addr))
	if !found {
		return loadbalancer.ServiceName{}, 0, false
	}
	isT1 := fe.Service.Annotations["loadbalancer.isovalent.com/type"] == "t1"
	return fe.ServiceName, fe.ID, isT1
}

func (mc *lbMetricsCollector) getOrAddEntry(svcName loadbalancer.ServiceName, addr loadbalancer.L3n4Addr) *backendMetricValue {
	key := backendMetricKey{svcName, addr}
	entry, ok := mc.backendMetrics[key]
	if !ok {
		entry = &backendMetricValue{}
		mc.backendMetrics[key] = entry
	}
	entry.updatedAt = mc.round

	return entry
}

func svcKeyToAddr(svcKey lbmaps.ServiceKey) loadbalancer.L3n4Addr {
	feIP := svcKey.GetAddress()
	feAddrCluster := cmtypes.MustAddrClusterFromIP(feIP)
	proto := loadbalancer.NewL4TypeFromNumber(svcKey.GetProtocol())
	feL3n4Addr := loadbalancer.NewL3n4Addr(proto, feAddrCluster, svcKey.GetPort(), svcKey.GetScope())
	return feL3n4Addr
}

func ctKeyToAddr(ctKey *ctmap.CtKey4Global) loadbalancer.L3n4Addr {
	feIP := ctKey.GetDestAddr()
	feAddrCluster := cmtypes.AddrClusterFrom(feIP, 0)
	proto := loadbalancer.NewL4TypeFromNumber(uint8(ctKey.NextHeader))
	feL3n4Addr := loadbalancer.NewL3n4Addr(proto, feAddrCluster, ctKey.SourcePort, loadbalancer.ScopeExternal)
	return feL3n4Addr
}

func beValueToAddr(beValue lbmaps.BackendValue) loadbalancer.L3n4Addr {
	beAddrCluster := beValue.GetAddress()
	proto := loadbalancer.NewL4TypeFromNumber(beValue.GetProtocol())
	beL3n4Addr := loadbalancer.NewL3n4Addr(proto, beAddrCluster, beValue.GetPort(), 0)
	return beL3n4Addr
}
