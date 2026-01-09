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

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/u8proto"
)

type serviceCacheEntry struct {
	namespace string
	name      string
	revNat    uint16
}

// lbMetricsCollector implements Prometheus Collector interface and store the state of the metrics collector
type lbMetricsCollector struct {
	// lbServiceCache maps LB frontend addresses (ip:port/proto) to the related service's name and RevNAT ID
	lbServiceCache map[string]serviceCacheEntry
	serviceSync    chan struct{}

	// prevLbCtEntries stores a snapshot of the LB CT entries
	prevLbCtEntries map[*ctmap.CtKey4Global]*ctmap.CtEntry

	// lbBytes maps frontends -> backends -> bytes count for a given (frontend, backend) tuple
	lbBytes map[string]map[string]uint64
	// lbBytes maps frontends -> backends -> packets count for a given (frontend, backend) tuple
	lbPackets map[string]map[string]uint64
	// lbOpenConnections is a counter for the number of open connections
	lbOpenConnections int
	// lbBytes maps frontends -> backends -> healthcheck status for a given (frontend, backend) tuple
	lbHealthcheckStatus map[string]map[string]bool

	lock.Mutex

	// services resource.Resource[*slim_corev1.Service]
	ct4Maps []*ctmap.Map

	lbBytesDesc             *prometheus.Desc
	lbPacketsDesc           *prometheus.Desc
	lbOpenConnectionsDesc   *prometheus.Desc
	lbHealthcheckStatusDesc *prometheus.Desc

	lbmaps lbmaps.LBMaps

	logger *slog.Logger
}

func newLBMetricsCollector(params collectorParams) *lbMetricsCollector {
	ct4Maps := ctmap.Maps(true, false)

	return &lbMetricsCollector{
		lbServiceCache: make(map[string]serviceCacheEntry),
		serviceSync:    make(chan struct{}),

		lbBytes:             make(map[string]map[string]uint64),
		lbPackets:           make(map[string]map[string]uint64),
		lbOpenConnections:   0,
		lbHealthcheckStatus: make(map[string]map[string]bool),

		// services: params.Services,
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

	for frontend, backends := range mc.lbBytes {
		for backend, bytes := range backends {
			ch <- prometheus.MustNewConstMetric(mc.lbBytesDesc, prometheus.CounterValue, float64(bytes), frontend, backend)
		}
	}
	for frontend, bes := range mc.lbPackets {
		for be, packets := range bes {
			ch <- prometheus.MustNewConstMetric(mc.lbPacketsDesc, prometheus.CounterValue, float64(packets), frontend, be)
		}
	}
	ch <- prometheus.MustNewConstMetric(mc.lbOpenConnectionsDesc, prometheus.GaugeValue, float64(mc.lbOpenConnections))
	for frontend, backendss := range mc.lbHealthcheckStatus {
		for backends, status := range backendss {
			s := 0
			if status {
				s = 1
			}
			ch <- prometheus.MustNewConstMetric(mc.lbHealthcheckStatusDesc, prometheus.GaugeValue, float64(s), frontend, backends)
		}
	}
}

// lbServiceCacheUpdater listens to service events and updates the LB service cache accordingly
//
//lint:ignore U1000 ignoring this while v1.Service will be replaced with statedb
func (mc *lbMetricsCollector) lbServiceCacheUpdater(ctx context.Context, event resource.Event[*slim_corev1.Service]) error {
	service := event.Object

	if event.Kind == resource.Sync {
		close(mc.serviceSync)
		event.Done(nil)
		return nil
	}

	// only add T1 services to the cache
	if service.Annotations["loadbalancer.isovalent.com/type"] != "t1" {
		event.Done(nil)
		return nil
	}

	mc.Lock()
	for _, frontendIP := range service.Status.LoadBalancer.Ingress {
		for _, frontendPort := range service.Spec.Ports {
			frontendAddr := formatFrontendAddr(frontendIP.IP, uint16(frontendPort.Port), string(frontendPort.Protocol))

			switch event.Kind {
			case resource.Upsert:
				if len(service.OwnerReferences) == 0 {
					mc.logger.Warn("Service is missing reference to LBService owner")
				} else {
					mc.lbServiceCache[frontendAddr] = serviceCacheEntry{namespace: service.Namespace, name: service.OwnerReferences[0].Name}
				}
			case resource.Delete:
				delete(mc.lbServiceCache, frontendAddr)
			}
		}
	}
	mc.Unlock()

	event.Done(nil)
	return nil
}

func (mc *lbMetricsCollector) fetchMetrics(ctx context.Context) error {
	select {
	case <-mc.serviceSync:
	default:
		return nil
	}

	mc.Lock()
	defer mc.Unlock()

	mc.lbOpenConnections = 0

	// Iterate the backend map to collect a list of all backends
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
		return err
	}

	// Iterate the service map to collect the health status of all LB services
	mc.lbHealthcheckStatus = make(map[string]map[string]bool)

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

		frontendAddr := formatFrontendAddr(serviceKey.Address.String(), serviceKey.Port, u8proto.U8proto(serviceKey.Proto).String())

		// ignore non LB services
		service, ok := mc.lbServiceCache[frontendAddr]
		if !ok {
			return
		}

		service.revNat = serviceVal.RevNat
		mc.lbServiceCache[frontendAddr] = service

		// lookup the service's backend from the cache
		serviceBackend, ok := backends[loadbalancer.BackendID(serviceVal.BackendID)]
		if !ok {
			return
		}

		frontendFullName := fmt.Sprintf("%s_%s", service.namespace, service.name)

		// and update the health status of the service's backend
		serviceBackends, ok := mc.lbHealthcheckStatus[frontendFullName]
		if !ok {
			serviceBackends = make(map[string]bool)
		}
		serviceBackends[serviceBackend.Address.String()] = serviceVal.GetFlags() == 0
		mc.lbHealthcheckStatus[frontendFullName] = serviceBackends
	}
	if err := mc.lbmaps.DumpService(serviceCallback); err != nil {
		mc.logger.Error("Cannot dump service map, LB metrics may be incomplete", logfields.Error, err)
		return err
	}

	// lbCtEntries collects all the LB related CT entries
	lbCtEntries := map[*ctmap.CtKey4Global]*ctmap.CtEntry{}

	ctMapCallback := func(key bpf.MapKey, value bpf.MapValue) {
		ctKey := key.(*ctmap.CtKey4Global).ToHost().(*ctmap.CtKey4Global)
		ctValue := value.(*ctmap.CtEntry)

		frontendAddr := formatFrontendAddr(ctKey.DestAddr.String(), ctKey.SourcePort, ctKey.NextHeader.String())

		// skip entry if it's not related to an LB service
		service, ok := mc.lbServiceCache[frontendAddr]
		if !ok {
			return
		}

		if ctValue.RevNAT != service.revNat {
			return
		}

		lbCtEntries[ctKey] = ctValue

		// lookup the CT entry's backend from the cache
		backend, ok := backends[loadbalancer.BackendID(ctValue.BackendID)]
		if !ok {
			return
		}

		// calculate the deltas between the current CT entry's counters and the previous one's (if it exists)
		deltaBytes := ctValue.Bytes
		deltaPackets := ctValue.Packets
		if prevCtValue, ok := mc.prevLbCtEntries[ctKey]; ok {
			deltaBytes -= prevCtValue.Bytes
			deltaPackets -= prevCtValue.Packets
		}

		frontendFullName := fmt.Sprintf("%s_%s", service.namespace, service.name)
		backendAddr := backend.Address.String()

		// and increment the bytes and packets counters by the related deltas
		lbBytesBackends, ok := mc.lbBytes[frontendFullName]
		if !ok {
			lbBytesBackends = make(map[string]uint64)
		}
		lbBytesBackends[backendAddr] += deltaBytes
		mc.lbBytes[frontendFullName] = lbBytesBackends

		lbPacketsBackends, ok := mc.lbPackets[frontendFullName]
		if !ok {
			lbPacketsBackends = make(map[string]uint64)
		}
		lbPacketsBackends[backendAddr] += deltaPackets
		mc.lbPackets[frontendFullName] = lbPacketsBackends

		mc.lbOpenConnections += 1
	}
	for _, ctMap := range mc.ct4Maps {
		if err := ctMap.DumpWithCallback(ctMapCallback); err != nil {
			mc.logger.Error("Cannot dump CT map, LB metrics may be incomplete", logfields.Error, err)
			return err
		}
	}

	mc.prevLbCtEntries = lbCtEntries

	return nil
}

func formatFrontendAddr(ip string, port uint16, protocol string) string {
	return fmt.Sprintf("%s:%d/%s", ip, port, protocol)
}
