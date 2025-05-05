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
	"log/slog"
	"maps"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/sets"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service"
)

var (
	sName = lb.ServiceName{
		Namespace: "test",
		Name:      "foo",
	}
	sAddr     = *lb.NewL3n4Addr(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.1"), 80, 0)
	beAddr1   = *lb.NewL3n4Addr(lb.TCP, cmtypes.MustParseAddrCluster("10.1.1.1"), 8080, 0)
	beAddr2   = *lb.NewL3n4Addr(lb.TCP, cmtypes.MustParseAddrCluster("10.1.1.2"), 8080, 0)
	backends1 = []*lb.LegacyBackend{
		lb.NewLegacyBackend(0, lb.TCP, beAddr1.AddrCluster, beAddr1.Port),
		lb.NewLegacyBackend(0, lb.TCP, beAddr2.AddrCluster, beAddr2.Port),
	}
	backends2 = []*lb.LegacyBackend{
		lb.NewBackendWithState(0, lb.TCP, beAddr1.AddrCluster, beAddr1.Port, 0, lb.BackendStateMaintenance),
		lb.NewBackendWithState(0, lb.TCP, beAddr2.AddrCluster, beAddr2.Port, 0, lb.BackendStateTerminating),
	}
	// Default config
	cfg = map[string]string{
		"service.cilium.io/health-check-probe-interval":      "3ms",
		"service.cilium.io/health-check-probe-timeout":       "1ms",
		"service.cilium.io/health-check-threshold-healthy":   "1",
		"service.cilium.io/health-check-threshold-unhealthy": "1",
		"service.cilium.io/health-check-quarantine-timeout":  "20ms",
	}
)

type TestHealthChecker struct {
	Events chan TestHealthCheckCBEvent
	hc     *HealthChecker
}

type TestHealthCheckCBEvent struct {
	beAddr  lb.L3n4Addr
	beState lb.BackendState
}

type TestProber struct {
	probes map[probeParams]ProbeData
	probCh chan ProbeData
}

type probeParams struct {
	beAddr beAddr
}

func (p *TestProber) sendTCPProbe(config HealthCheckConfig, svcAddr, beAddr lb.L3n4Addr, probeOut chan ProbeData) {
	if len(p.probes) == 0 {
		po := <-p.probCh
		probeOut <- po
		return
	}
	select {
	case po := <-p.probCh:
		probeOut <- po
	default:
		params := probeParams{
			beAddr: beAddr,
		}
		probeOut <- p.probes[params]
	}
}

func (p *TestProber) sendUDPProbe(config HealthCheckConfig, svcAddr, beAddr lb.L3n4Addr, probeOut chan ProbeData) {
	if len(p.probes) == 0 {
		po := <-p.probCh
		probeOut <- po
		return
	}
	select {
	case po := <-p.probCh:
		probeOut <- po
	default:
		params := probeParams{
			beAddr: beAddr,
		}
		probeOut <- p.probes[params]
	}
}

func (p *TestProber) sendL7Probe(config HealthCheckConfig, svcAddr, beAddr lb.L3n4Addr, probeOut chan ProbeData) {
	if len(p.probes) == 0 {
		po := <-p.probCh
		probeOut <- po
		return
	}
	select {
	case po := <-p.probCh:
		probeOut <- po
	default:
		params := probeParams{
			beAddr: beAddr,
		}
		probeOut <- p.probes[params]
	}
}

func (hc *TestHealthChecker) HealthCheckCBTest(event int, data any) {
	switch event {
	case service.HealthCheckCBBackendEvent:
		if d, ok := data.(service.HealthCheckCBBackendEventData); ok {
			hc.Events <- TestHealthCheckCBEvent{
				beAddr:  d.BeAddr,
				beState: d.BeState,
			}
		}
	}
}

type probesMap map[probeParams]ProbeData

func addProbeEntry(pm probesMap, beAddr lb.L3n4Addr, pd ProbeData) {
	pp := probeParams{beAddr: beAddr}
	pm[pp] = pd
}

func setupTest(t *testing.T, prober Prober) *TestHealthChecker {
	option.Config.EnableSocketLB = true
	thc := &TestHealthChecker{
		Events: make(chan TestHealthCheckCBEvent),
	}

	logger := slog.New(slog.DiscardHandler)

	thc.hc = newHealthChecker(logger)
	thc.hc.SetCallback(thc.HealthCheckCBTest)

	if prober != nil {
		// using test prober directly
		thc.hc.prober = prober
	}

	go thc.hc.run()
	t.Cleanup(thc.hc.Stop)

	return thc
}

func TestHealthChecker_UpsertService(t *testing.T) {
	pm := make(probesMap)
	addProbeEntry(pm, beAddr1, ProbeData{healthy: true})
	addProbeEntry(pm, beAddr2, ProbeData{healthy: false})
	thc := setupTest(t, &TestProber{probes: pm})

	thc.hc.UpsertService(sAddr, sName, lb.SVCTypeLoadBalancer, cfg, backends1)

	// Check for quarantined backend event for the unhealthy backend.
	ev := <-thc.Events
	assert.Equal(t, beAddr2, ev.beAddr)
	assert.Equal(t, lb.BackendStateQuarantined, ev.beState)

	// Update service backends
	bes := []*lb.LegacyBackend{backends1[0]}

	thc.hc.UpsertService(sAddr, sName, lb.SVCTypeClusterIP, cfg, bes)

	// Add a service with backend states that are not health-checked.
	sAddr2 := *lb.NewL3n4Addr(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.2"), 80, 0)
	sName2 := sName
	sName2.Name = "bar"
	thc.hc.UpsertService(sAddr2, sName2, lb.SVCTypeClusterIP, cfg, backends2)

	// No TestHealthCheckCBEvent events to drain
}

func TestHealthChecker_DeleteService(t *testing.T) {
	thc := setupTest(t, nil)
	hc := thc.hc
	hc.svcMap[sAddr] = []beAddr{beAddr1, beAddr2}
	hc.beMap[beAddr1] = sets.New(sAddr)
	hc.beMap[beAddr2] = sets.New(sAddr)
	t1 := time.NewTicker(3 * time.Millisecond)
	t2 := time.NewTicker(3 * time.Millisecond)
	c1 := make(chan struct{})
	c2 := make(chan struct{})
	hc.beHealthMap[sAddr] = map[beAddr]*healthData{
		beAddr1: {ticker: &healthTicker{ticker: t1, stop: c1}},
		beAddr2: {ticker: &healthTicker{ticker: t2, stop: c2}},
	}

	hc.DeleteService(sAddr, sName)

	<-c1
	<-c2
}

func TestHealthChecker_UpsertDeleteServiceWithCommonBackend(t *testing.T) {
	pm := make(probesMap)
	addProbeEntry(pm, beAddr1, ProbeData{healthy: true})
	addProbeEntry(pm, beAddr2, ProbeData{healthy: false})
	pch := make(chan ProbeData, 10)
	thc := setupTest(t, &TestProber{probes: pm, probCh: pch})

	sAddr2 := *lb.NewL3n4Addr(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.2"), 80, 0)
	sName2 := sName
	sName2.Name = "bar"
	bes := []*lb.LegacyBackend{backends1[1]}

	thc.hc.UpsertService(sAddr, sName, lb.SVCTypeLoadBalancer, cfg, backends1)
	// Add a service with common backend.
	thc.hc.UpsertService(sAddr2, sName2, lb.SVCTypeLoadBalancer, cfg, bes)

	// Check for quarantined backend event for the unhealthy backend.
	ev := <-thc.Events
	assert.Equal(t, beAddr2, ev.beAddr)
	assert.Equal(t, lb.BackendStateQuarantined, ev.beState)

	ev = <-thc.Events
	assert.Equal(t, beAddr2, ev.beAddr)
	assert.Equal(t, lb.BackendStateQuarantined, ev.beState)

	// Delete one of the services.
	thc.hc.DeleteService(sAddr, sName)

	// Ensure that service is deleted before sending the probe.
	// Otherwise, the probe might be consumed by the wrong backend health check probe.
	assert.Eventually(t, func() bool {
		_, ok := thc.hc.svcMap[sAddr]
		return !ok
	}, 5*time.Second, 10*time.Millisecond)

	// Toggle backend state.
	pch <- ProbeData{healthy: true}

	// Check for active backend event for the backend.
	ev = <-thc.Events
	assert.Equal(t, beAddr2, ev.beAddr)
	assert.Equal(t, lb.BackendStateActive, ev.beState)

	thc.hc.DeleteService(sAddr2, sName2)
}

func TestHealthChecker_UpsertServiceWithHealthCheckConfig(t *testing.T) {
	pm := make(probesMap)
	pch := make(chan ProbeData, 10)
	thc := setupTest(t, &TestProber{probes: pm, probCh: pch})
	cc := maps.Clone(cfg)
	// Set the threshold for healthy and unhealthy probes.
	cc["service.cilium.io/health-check-threshold-healthy"] = "3"
	cc["service.cilium.io/health-check-threshold-unhealthy"] = "4"
	bes := []*lb.LegacyBackend{backends1[0]}

	thc.hc.UpsertService(sAddr, sName, lb.SVCTypeLoadBalancer, cc, bes)

	for i := 1; i <= 4; i++ {
		pch <- ProbeData{healthy: false}
	}
	// Check the HealthCheckUpdateCB after configured number of unhealthy probe threshold.
	ev := <-thc.Events

	assert.Equal(t, beAddr1, ev.beAddr)
	assert.Equal(t, lb.BackendStateQuarantined, ev.beState)

	// Toggle the probes to healthy.
	for i := 1; i <= 3; i++ {
		pch <- ProbeData{healthy: true}
	}

	// Check the HealthCheckUpdateCB after configured number of healthy probe threshold.
	ev = <-thc.Events
	assert.Equal(t, beAddr1, ev.beAddr)
	assert.Equal(t, lb.BackendStateActive, ev.beState)

	thc.hc.DeleteService(sAddr, sName)

	// Set the QuarantineTimeout, and check when probes are resumed for a quarantined backend.
	cc2 := maps.Clone(cfg)
	cc2["service.cilium.io/health-check-quarantine-timeout"] = "5ms"
	sAddr2 := *lb.NewL3n4Addr(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.2"), 80, 0)
	sName2 := sName
	sName2.Name = "bar"
	bes2 := []*lb.LegacyBackend{backends1[0]}

	thc.hc.UpsertService(sAddr2, sName2, lb.SVCTypeLoadBalancer, cc2, bes2)

	for i := 1; i <= 1; i++ {
		pch <- ProbeData{healthy: false}
	}
	// Backend quarantined
	ev = <-thc.Events
	t1 := time.Now()

	// Probes resumed after QuarantineTimeout for the quarantined backend.
	pch <- ProbeData{healthy: true}
	ev = <-thc.Events
	t2 := time.Now()

	assert.GreaterOrEqual(t, t2.Sub(t1), 5*time.Millisecond)
}

func TestHealthChecker_UpsertServiceWithHealthCheckConfigUpdate(t *testing.T) {
	pch := make(chan ProbeData, 10)
	thc := setupTest(t, &TestProber{probCh: pch})
	cc := maps.Clone(cfg)
	// Set the threshold for healthy and unhealthy probes.
	cc["service.cilium.io/health-check-threshold-healthy"] = "3"
	cc["service.cilium.io/health-check-threshold-unhealthy"] = "3"
	bes := []*lb.LegacyBackend{backends1[0]}
	sAddr2 := *lb.NewL3n4Addr(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.2"), 80, 0)
	sName2 := sName
	sName2.Name = "bar"

	thc.hc.UpsertService(sAddr, sName, lb.SVCTypeLoadBalancer, cc, bes)
	thc.hc.UpsertService(sAddr2, sName2, lb.SVCTypeLoadBalancer, cfg, bes)

	for i := 1; i <= 3; i++ {
		pch <- ProbeData{healthy: false}
	}
	// Check the HealthCheckUpdateCB after configured number of unhealthy probe threshold.
	ev := <-thc.Events
	assert.Equal(t, beAddr1, ev.beAddr)
	assert.Equal(t, lb.BackendStateQuarantined, ev.beState)

	// Update the config.
	// Set ThresholdUnhealthy >> ThresholdHealthy to be able to control test
	// assertions as health probes continue to run in the background.
	cc["service.cilium.io/health-check-threshold-healthy"] = "10"
	cc["service.cilium.io/health-check-threshold-unhealthy"] = "4"

	thc.hc.UpsertService(sAddr, sName, lb.SVCTypeLoadBalancer, cc, bes)

	/// mark backend as failing first - otherwise the active backend won't be reported as it was already active
	for i := 1; i <= 4; i++ {
		pch <- ProbeData{healthy: false}
	}

	ev = <-thc.Events
	assert.Equal(t, beAddr1, ev.beAddr)
	assert.Equal(t, lb.BackendStateQuarantined, ev.beState)

	// Toggle the probes to healthy.
	for i := 1; i <= 10; i++ {
		pch <- ProbeData{healthy: true}
	}

	// Check the HealthCheckUpdateCB after the updated healthy probe threshold.
	ev = <-thc.Events
	assert.Equal(t, beAddr1, ev.beAddr)
	assert.Equal(t, lb.BackendStateActive, ev.beState)

	// Disable service health check.
	cc = map[string]string{}

	thc.hc.UpsertService(sAddr, sName, lb.SVCTypeLoadBalancer, cc, bes)
}
