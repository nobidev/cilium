// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package healthchecker

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/enterprise/pkg/annotation"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/time"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "svc-health-checker")

// backendAddrKey is used as a key to context.Value(). It is used
// to pass the backend address.
type backendAddrKey struct{}

type HealthChecker struct {
	datapathLbOnly bool
	// Fixme: Replace slice with a set of backends
	svcMap          map[svcAddr][]beAddr
	svcMapLock      lock.RWMutex
	configMap       map[svcAddr]HealthCheckConfig
	configMapLock   lock.Mutex
	beMap           map[beAddr]sets.Set[svcAddr]
	beMapLock       lock.RWMutex
	beHealthMap     map[svcAddr]map[beAddr]*healthData
	beHealthMapLock lock.RWMutex
	svcEvents       chan svcEvent
	cb              service.HealthCheckCallbackFunc
	prober          Prober
	close           chan struct{}
}

type Prober interface {
	sendTCPProbe(config HealthCheckConfig, svcAddr, beAddr lb.L3n4Addr, probeOut chan ProbeData)
	sendUDPProbe(config HealthCheckConfig, svcAddr, beAddr lb.L3n4Addr, probeOut chan ProbeData)
	sendL7Probe(config HealthCheckConfig, svcAddr, beAddr lb.L3n4Addr, probeOut chan ProbeData)
}

type ProbeData struct {
	ts      time.Time
	healthy bool
	message string
}

const (
	eventsChanSize    = 5
	SO_MARK           = 36
	MARK_MAGIC_HEALTH = 0x0D00
)

const (
	SvcEventUpsert = iota
	SvcEventDelete
	SvcEventConfigUpdate
	SvcEventConfigDisabled
)

type svcAddr = lb.L3n4Addr

type beAddr = lb.L3n4Addr

type healthData struct {
	ticker healthTicker
	probe  ProbeData
}

type healthTicker struct {
	ticker  *time.Ticker
	stop    chan struct{}
	stopped chan struct{}
	config  HealthCheckConfig
}

type svcEvent struct {
	evType            int
	addr              svcAddr
	config            HealthCheckConfig
	unhealthyBackends sets.Set[beAddr] // Can only be set for SvcEventUpsert event
}

func (hc *HealthChecker) SetCallback(cb service.HealthCheckCallbackFunc) {
	hc.cb = cb
}

func (hc *HealthChecker) UpsertService(svcAddr lb.L3n4Addr, name lb.ServiceName, svcType lb.SVCType, svcAnnotations map[string]string, backends []*lb.Backend) {
	if !hc.datapathLbOnly {
		return
	}

	svcHealthCheckConfig := getAnnotationHealthCheckConfig(svcAnnotations)

	tmpHealthCheckConfig := HealthCheckConfig{
		State: HealthCheckDisabled,
	}
	if svcType != lb.SVCTypeLoadBalancer {
		svcHealthCheckConfig = tmpHealthCheckConfig
	}

	// Check if the health check config has been updated.
	hc.configMapLock.Lock()
	defer hc.configMapLock.Unlock()
	prevConfig, configExists := hc.configMap[svcAddr]
	if !configExists {
		if svcHealthCheckConfig.State == HealthCheckDisabled {
			return
		}
		hc.configMap[svcAddr] = svcHealthCheckConfig
	}
	// Fixme: (tbd) health check exception: do we want to quarantine kube-api server in case of failures???
	if strings.ToLower(name.Name) == "kubernetes" {
		log.Infof("hc-debug skip health checks for svc %s", name)
		return
	}
	log.Infof("hc-debug: service: %s, type: %s, config: %s", name, svcType, svcHealthCheckConfig)
	hc.svcMapLock.Lock()
	defer hc.svcMapLock.Unlock()

	bes := make([]beAddr, 0, len(backends))
	prevBes, ok := hc.svcMap[svcAddr]
	backendUpdate := false
	unhealthyBackends := sets.New(lb.L3n4Addr{})
	if ok {
		for _, newBe := range backends {
			// Backends in these states are not health-checked.
			if newBe.State == lb.BackendStateMaintenance || newBe.State == lb.BackendStateTerminating {
				continue
			}
			if newBe.State == lb.BackendStateQuarantined {
				unhealthyBackends.Insert(newBe.L3n4Addr)
			}
			found := false
			for _, prevBe := range prevBes {
				if prevBe.DeepEqual(&newBe.L3n4Addr) {
					// Backend still exists, so preserve previous data.
					found = true
					bes = append(bes, prevBe)
					break
				}
			}
			if !found {
				// New svc backend
				bes = append(bes, newBe.L3n4Addr)
				backendUpdate = true
			}
		}
	} else {
		backendUpdate = true
		for _, be := range backends {
			// Backends in these states are not health-checked.
			if be.State == lb.BackendStateMaintenance || be.State == lb.BackendStateTerminating {
				continue
			}
			bes = append(bes, be.L3n4Addr)
		}
	}
	// Check for stale backends.
	for i := range prevBes {
		found := false
		for _, be := range bes {
			if prevBes[i].DeepEqual(&be) {
				found = true
				break
			}
		}
		if !found {
			hc.removeServiceBackend(svcAddr, prevBes[i], false)
			backendUpdate = true
		}
	}
	hc.svcMap[svcAddr] = bes

	// Service backends updated
	if backendUpdate {
		log.Infof("hc-debug start health check %v", svcAddr)
		hc.svcEvents <- svcEvent{
			evType:            SvcEventUpsert,
			addr:              svcAddr,
			config:            svcHealthCheckConfig,
			unhealthyBackends: unhealthyBackends,
		}
	}
	// Service config updated
	if configExists && !prevConfig.DeepEqual(&svcHealthCheckConfig) {
		switch svcHealthCheckConfig.State {
		case HealthCheckEnabledNative:
			hc.configMap[svcAddr] = svcHealthCheckConfig
			// Send updates to all the service backends health check probers.
			hc.svcEvents <- svcEvent{
				evType: SvcEventConfigUpdate,
				addr:   svcAddr,
				config: svcHealthCheckConfig,
			}
		case HealthCheckDisabled:
			log.Infof("hc-debug service health checks disabled %v", svcAddr)
			delete(hc.configMap, svcAddr)
			// Send updates to all the service backends health check probers.
			hc.svcEvents <- svcEvent{
				evType: SvcEventConfigDisabled,
				addr:   svcAddr,
				config: svcHealthCheckConfig,
			}
		}
	}
}

func (hc *HealthChecker) DeleteService(svcAddr lb.L3n4Addr, name lb.ServiceName) {
	log.Infof("hc-debug stop health checks for deleted service %s", name)
	hc.svcEvents <- svcEvent{
		evType: SvcEventDelete,
		addr:   svcAddr,
	}
}

// newHealthChecker provides an instance of the HealthChecker.
func newHealthChecker(datapathLbOnly bool) *HealthChecker {
	return &HealthChecker{
		datapathLbOnly: datapathLbOnly,
		svcMap:         make(map[svcAddr][]beAddr),
		beMap:          make(map[beAddr]sets.Set[svcAddr]),
		beHealthMap:    make(map[svcAddr]map[beAddr]*healthData),
		configMap:      make(map[svcAddr]HealthCheckConfig),
		prober:         &probeImpl{datapathLbOnly: datapathLbOnly},
		svcEvents:      make(chan svcEvent, eventsChanSize),
		close:          make(chan struct{}),
	}
}

func (hc *HealthChecker) run() {
	for {
		select {
		case event := <-hc.svcEvents:
			log.
				WithField("type", event.evType).
				WithField("addr", event.addr).
				Info("Handling Service Event")
			switch event.evType {
			case SvcEventUpsert:
				hc.startHealthCheck(event.addr, event.config, event.unhealthyBackends)
			case SvcEventDelete:
				hc.stopSvcHealthCheck(event.addr, false)
			case SvcEventConfigUpdate:
				hc.updateHealthChecks(event.addr, event.config)
			case SvcEventConfigDisabled:
				hc.stopSvcHealthCheck(event.addr, true)
			}
		case <-hc.close:
			hc.stopAllHealthChecks()
			return
		}
	}
}

// Fixme: Needs to be wired up.
func (hc *HealthChecker) Stop() {
	close(hc.close)
}

func (hc *HealthChecker) startHealthCheck(svcAddress lb.L3n4Addr, config HealthCheckConfig, unhealthyBackends sets.Set[lb.L3n4Addr]) {
	if len(unhealthyBackends) > 0 {
		hc.cb(service.HealthCheckCBSvcEvent, service.HealthCheckCBSvcEventData{
			SvcAddr: svcAddress,
		})
	}
	hc.svcMapLock.RLock()
	defer hc.svcMapLock.RUnlock()
	hc.beMapLock.Lock()
	defer hc.beMapLock.Unlock()
	bes := hc.svcMap[svcAddress]
	for _, be := range bes {
		_, ok := hc.beMap[be]
		if !ok {
			// New backend to be health checked
			hc.beMap[be] = sets.New[svcAddr]()
		}

		svcs := hc.beMap[be]
		if !svcs.Has(svcAddress) {
			// Backend is common to multiple services. Update the backend
			// services list, but don't send duplicate health probes.
			svcs.Insert(svcAddress)

			healthy := true
			if unhealthyBackends.Has(be) {
				// Backends could be marked unhealthy prior to agent restart, so
				// preserve the health state.
				healthy = false
			}
			go hc.sendHealthProbes(config, svcAddress, be, healthy)
		}
	}
}

func (hc *HealthChecker) stopSvcHealthCheck(svcAddr lb.L3n4Addr, reActivate bool) {
	hc.svcMapLock.Lock()
	defer hc.svcMapLock.Unlock()
	bes := hc.svcMap[svcAddr]
	for _, be := range bes {
		hc.removeServiceBackend(svcAddr, be, reActivate)
	}
	delete(hc.svcMap, svcAddr)
}

func (hc *HealthChecker) stopAllHealthChecks() {
	hc.svcMapLock.Lock()
	defer hc.svcMapLock.Unlock()
	for svc := range hc.svcMap {
		bes := hc.svcMap[svc]
		for _, be := range bes {
			hc.removeServiceBackend(svc, be, false)
		}
	}
}

func (hc *HealthChecker) stopBackendHealthCheck(svcAddr lb.L3n4Addr, be lb.L3n4Addr) {
	hc.beHealthMapLock.Lock()
	defer hc.beHealthMapLock.Unlock()
	if beHealths, ok := hc.beHealthMap[svcAddr]; ok {
		// Stop health checks for the backend.
		if beh, ok := beHealths[be]; ok {
			beh.stop()
			delete(hc.beHealthMap[svcAddr], be)
		}
	}
}

func (hc *HealthChecker) removeServiceBackend(svcAddr lb.L3n4Addr, beAddr lb.L3n4Addr, reActivate bool) {
	log.
		WithField("svc", svcAddr).
		WithField("be", beAddr).
		WithField("reactivate", reActivate).
		Info("Remove Service Backend")

	hc.beMapLock.Lock()
	defer hc.beMapLock.Unlock()
	var deleteBe bool
	if svcs, ok := hc.beMap[beAddr]; ok {
		svcs.Delete(svcAddr)
		hc.stopBackendHealthCheck(svcAddr, beAddr)
		if svcs.Len() == 0 {
			deleteBe = true
		}
	}

	// Delete backend if it's no longer used by a Service
	if deleteBe {
		delete(hc.beMap, beAddr)
		if reActivate {
			hc.cb(service.HealthCheckCBBackendEvent, service.HealthCheckCBBackendEventData{
				SvcAddr: svcAddr,
				BeAddr:  beAddr,
				BeState: lb.BackendStateActive,
			})
		}
	}
}

func (hc *HealthChecker) updateHealthChecks(svcAddr lb.L3n4Addr, config HealthCheckConfig) {
	hc.svcMapLock.Lock()
	defer hc.svcMapLock.Unlock()

	bes := hc.svcMap[svcAddr]
	for _, be := range bes {
		hc.beHealthMapLock.Lock()
		beMap, ok := hc.beHealthMap[svcAddr]
		if ok {
			if beHD, ok := beMap[be]; ok {
				healthy := beHD.probe.healthy
				if !beHD.ticker.config.DeepEqual(&config) {
					beHD.ticker.config = config
					log.Infof("hc-debug health config update %v -> %v", beHD.ticker.config, config)
					beHD.stop()
					<-beHD.ticker.stopped
					// Trigger health probes with the updated configs, but preserve the
					// previously set health.
					go hc.sendHealthProbes(config, svcAddr, be, healthy)
				}
			}
		}
		hc.beHealthMapLock.Unlock()
	}
}

type probeImpl struct {
	datapathLbOnly bool
}

func (hc *HealthChecker) sendHealthProbes(config HealthCheckConfig, svcAddr, beAddr lb.L3n4Addr, healthy bool) {
	ht := healthTicker{
		ticker:  time.NewTicker(config.ProbeInterval),
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
		config:  config,
	}
	probeInitial := ProbeData{
		ts:      time.Now(),
		healthy: healthy,
	}
	health := healthData{
		ticker: ht,
		probe:  probeInitial,
	}
	probeOut := make(chan ProbeData, 1)
	waitingOnProbe := false
	probeHealthyCount := 0
	probeUnhealthyCount := 0

	hc.updateBackendHealthData(svcAddr, beAddr, health)
	for {
		select {
		case <-ht.stop:
			log.Infof("health probes stopped %v - %v", svcAddr, beAddr)
			close(ht.stopped)
			return
		case <-ht.ticker.C:
			if !waitingOnProbe {
				log.Infof("hc-debug sending health probe for svc %v and be %v", svcAddr, beAddr)
				if config.L7 {
					waitingOnProbe = true
					go hc.prober.sendL7Probe(config, svcAddr, beAddr, probeOut)
				} else {
					switch beAddr.Protocol {
					// Protocol information may not be available in loadbalancer mode.
					case lb.TCP:
						waitingOnProbe = true
						go hc.prober.sendTCPProbe(config, svcAddr, beAddr, probeOut)
					case lb.UDP:
						waitingOnProbe = true
						go hc.prober.sendUDPProbe(config, svcAddr, beAddr, probeOut)
					}
				}
			}
		case newProbe := <-probeOut:
			waitingOnProbe = false
			if health.probe.healthy != newProbe.healthy {
				if newProbe.healthy {
					probeHealthyCount++
					if probeHealthyCount < config.ThresholdHealthy {
						continue
					}
					log.WithFields(logrus.Fields{
						"config":  config,
						"svc":     svcAddr,
						"be":      beAddr,
						"message": newProbe.message,
					}).Info("Marking service backend as active")
					hc.cb(service.HealthCheckCBBackendEvent, service.HealthCheckCBBackendEventData{
						SvcAddr: svcAddr,
						BeAddr:  beAddr,
						BeState: lb.BackendStateActive,
					})
					probeHealthyCount = 0
				} else {
					probeUnhealthyCount++
					if probeUnhealthyCount < config.ThresholdUnhealthy {
						continue
					}
					log.WithFields(logrus.Fields{
						"config":  config,
						"svc":     svcAddr,
						"be":      beAddr,
						"message": newProbe.message,
					}).Info("Marking service backend as quarantined")
					hc.cb(service.HealthCheckCBBackendEvent, service.HealthCheckCBBackendEventData{
						SvcAddr: svcAddr,
						BeAddr:  beAddr,
						BeState: lb.BackendStateQuarantined,
					})
					probeUnhealthyCount = 0
					time.Sleep(config.QuarantineTimeout)
				}
			}
			hc.updateBackendHealthProbeData(svcAddr, beAddr, newProbe)
			health.probe = newProbe
		}
	}
}

func (hc *HealthChecker) updateBackendHealthData(svcAddr lb.L3n4Addr, be lb.L3n4Addr, health healthData) {
	hc.beHealthMapLock.Lock()
	defer hc.beHealthMapLock.Unlock()

	_, ok := hc.beHealthMap[svcAddr]
	if !ok {
		hc.beHealthMap[svcAddr] = map[beAddr]*healthData{}
	}

	hc.beHealthMap[svcAddr][be] = &health
}

func (hc *HealthChecker) updateBackendHealthProbeData(svc lb.L3n4Addr, be lb.L3n4Addr, probe ProbeData) {
	hc.beHealthMapLock.Lock()
	defer hc.beHealthMapLock.Unlock()

	if _, ok := hc.beHealthMap[svc]; !ok {
		return
	}

	if _, ok := hc.beHealthMap[svc][be]; !ok {
		return
	}

	hc.beHealthMap[svc][be].probe = probe
}

func (pr *probeImpl) dialerConnSetup(ctx context.Context, network string, address string, c syscall.RawConn) error {
	var errCB error
	var fn func(uintptr)

	if !pr.datapathLbOnly || !option.Config.EnableHealthDatapath {
		return nil
	}
	backend := ctx.Value(backendAddrKey{}).(string)

	log.
		WithField("network", network).
		WithField("address", address).
		WithField("backend", backend).
		Info("dialerConnSetup")

	switch network {
	case "tcp4", "tcp6":
		tcpAddr, err := net.ResolveTCPAddr(network, backend)
		if err != nil {
			return err
		}

		fn = func(s uintptr) {
			errCB = syscall.SetsockoptInt(int(s), syscall.SOL_SOCKET, SO_MARK, MARK_MAGIC_HEALTH)
			if errCB == nil {
				if network == "tcp4" {
					sa := &syscall.SockaddrInet4{
						Port: tcpAddr.Port,
					}
					ip4 := tcpAddr.IP.To4()
					copy(sa.Addr[:], ip4)
					errCB = syscall.Bind(int(s), sa)
				} else {
					sa := &syscall.SockaddrInet6{
						Port: tcpAddr.Port,
					}
					ip6 := tcpAddr.IP.To16()
					copy(sa.Addr[:], ip6)
					errCB = syscall.Bind(int(s), sa)
				}
			}
		}
	case "udp4", "udp6":
		udpAddr, err := net.ResolveUDPAddr(network, backend)
		if err != nil {
			return err
		}
		fn = func(s uintptr) {
			errCB = syscall.SetsockoptInt(int(s), syscall.SOL_SOCKET, SO_MARK, MARK_MAGIC_HEALTH)
			if errCB == nil {
				if network == "udp4" {
					sa := &syscall.SockaddrInet4{
						Port: udpAddr.Port,
					}
					ip4 := udpAddr.IP.To4()
					copy(sa.Addr[:], ip4)
					errCB = syscall.Bind(int(s), sa)
				} else {
					sa := &syscall.SockaddrInet6{
						Port: udpAddr.Port,
					}
					ip6 := udpAddr.IP.To16()
					copy(sa.Addr[:], ip6)
					errCB = syscall.Bind(int(s), sa)
				}
			}
		}
	default:
		return nil
	}
	if err := c.Control(fn); err != nil {
		return err
	}
	if errCB != nil {
		return errCB
	}
	return nil
}

func (pr *probeImpl) sendTCPProbe(config HealthCheckConfig, svcAddr, beAddr lb.L3n4Addr, probeOut chan ProbeData) {
	d := net.Dialer{
		Timeout:        config.ProbeTimeout,
		ControlContext: pr.dialerConnSetup,
	}
	connAddr := getAddrStr(svcAddr)
	if !pr.datapathLbOnly || !option.Config.EnableHealthDatapath {
		connAddr = getAddrStr(beAddr)
	}
	ctx := context.WithValue(context.Background(), backendAddrKey{}, getAddrStr(beAddr))
	conn, err := d.DialContext(ctx, "tcp", connAddr)
	if err != nil {
		// Be conservative while failing a probe.
		if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENETUNREACH) || os.IsTimeout(err) {
			probeOut <- getProbeData(fmt.Errorf("err: %w", err))
			return
		}
		log.Debugf("Dial TCP failed while sending out probe to [%v]: %v", beAddr, err)
		probeOut <- getProbeData(nil)
		return
	}
	defer conn.Close()

	probe := getProbeData(nil)
	log.Infof("hc-debug health check success %v probe %v", beAddr, probe)

	probeOut <- probe
}

func (pr *probeImpl) sendUDPProbe(config HealthCheckConfig, svcAddr, beAddr lb.L3n4Addr, probeOut chan ProbeData) {
	d := net.Dialer{
		ControlContext: pr.dialerConnSetup,
	}
	connAddr := getAddrStr(svcAddr)
	if !pr.datapathLbOnly || !option.Config.EnableHealthDatapath {
		connAddr = getAddrStr(beAddr)
	}
	ctx := context.WithValue(context.Background(), backendAddrKey{}, getAddrStr(beAddr))
	// In the absence of flow control, the only definitive signal we can rely
	// on for checking if remote UDP server is up is the receipt of
	// ICMP_PORT_UNREACHABLE message.
	// These messages, however, can sometimes get dropped by middle boxes. The
	// health checker doesn't fail probes in such cases.
	// ECONNREFUSED only sent for connected UDP:
	// https://elixir.bootlin.com/linux/v6.0/source/net/ipv4/icmp.c#L130
	conn, err := d.DialContext(ctx, "udp", connAddr)
	if err != nil {
		log.Debugf("DialUDP() failed while sending out probe to [%v]: %v", beAddr, err)
		probeOut <- getProbeData(nil)
		return
	}
	defer conn.Close()
	// UDP send/receive blocks only when the buffer is full, so we need not set
	// the timeout here. But just in case...
	conn.SetDeadline(time.Now().Add(config.ProbeTimeout))
	if _, err = conn.Write([]byte("t")); err != nil {
		log.Debugf("Write() failed while sending out probe to [%v]: %v", beAddr, err)
		probeOut <- getProbeData(nil)
		return
	}
	_, err = bufio.NewReader(conn).ReadString('\n')
	var errno syscall.Errno
	if errors.As(err, &errno) {
		// ECONNREFUSED wraps ICMP_PORT_UNREACHABLE
		// https://elixir.bootlin.com/linux/v6.0/source/net/ipv4/icmp.c#L130
		if errors.Is(err, syscall.ECONNREFUSED) {
			log.Debugf("probe failed [%v]: %v", beAddr, err)
			probeOut <- getProbeData(fmt.Errorf("error: %w", err))
			return
		}
	} else if os.IsTimeout(err) {
		log.Debugf("probe failed [%v]: %v", beAddr, err)
		probeOut <- getProbeData(fmt.Errorf("error: %w", err))
		return
	}

	probe := getProbeData(nil)
	log.Infof("hc-debug health check success %v probe %v", beAddr, probe)

	probeOut <- probe
}

func getProbeData(err error) ProbeData {
	var probe ProbeData

	probe.ts = time.Now()
	if err == nil {
		probe.healthy = true
		probe.message = "success"
	} else {
		probe.healthy = false
		probe.message = fmt.Sprintf("failed: %v", err)
	}

	return probe
}

func getAddrStr(addr lb.L3n4Addr) string {
	portStr := strconv.FormatUint(uint64(addr.Port), 10)

	return addr.AddrCluster.String() + ":" + portStr
}

func (hd *healthData) stop() {
	hd.ticker.ticker.Stop()
	close(hd.ticker.stop)
}

func getAnnotationHealthCheckConfig(svcAnnotations map[string]string) HealthCheckConfig {
	hc := defaultHealthCheckConfig()

	if value, ok := svcAnnotations[annotation.ServiceHealthProbeInterval]; ok {
		if duration, err := time.ParseDuration(value); err == nil {
			hc.ProbeInterval = duration
			hc.State = HealthCheckEnabledNative
		}
	}
	if value, ok := svcAnnotations[annotation.ServiceHealthProbeTimeout]; ok {
		if duration, err := time.ParseDuration(value); err == nil {
			hc.ProbeTimeout = duration
		}
	}
	if value, ok := svcAnnotations[annotation.ServiceHealthQuarantineTimeout]; ok {
		if duration, err := time.ParseDuration(value); err == nil {
			hc.QuarantineTimeout = duration
		}
	}
	if value, ok := svcAnnotations[annotation.ServiceHealthThresholdHealthy]; ok {
		if threshold, err := strconv.Atoi(value); err == nil {
			hc.ThresholdHealthy = threshold
		}
	}
	if value, ok := svcAnnotations[annotation.ServiceHealthThresholdUnhealthy]; ok {
		if threshold, err := strconv.Atoi(value); err == nil {
			hc.ThresholdUnhealthy = threshold
		}
	}
	if value, ok := svcAnnotations[annotation.ServiceHealthHTTPPath]; ok {
		hc.HTTPPath = value
		hc.L7 = true
	}
	if value, ok := svcAnnotations[annotation.ServiceHealthHTTPHost]; ok {
		hc.HTTPHost = value
	}
	if value, ok := svcAnnotations[annotation.ServiceHealthHTTPMethod]; ok {
		value = strings.ToLower(value)
		switch value {
		case HealthCheckMethodGetString:
			hc.HTTPMethod = HealthCheckMethodGet
		case HealthCheckMethodHeadString:
			hc.HTTPMethod = HealthCheckMethodHead
		}
	}
	if value, ok := svcAnnotations[annotation.ServiceHealthHTTPScheme]; ok {
		value = strings.ToLower(value)
		switch value {
		case HealthCheckSchemeHTTPSString:
			hc.HTTPScheme = HealthCheckSchemeHTTPS
		case HealthCheckSchemeHTTPString:
			hc.HTTPScheme = HealthCheckSchemeHTTP
		}
	}

	return hc
}
