//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/tables"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

var ErrIPCacheInvalid = fmt.Errorf("agent IPCache map invalid")
var ErrWriteDisabled = fmt.Errorf("bpf IPCache writes disabled")

type bpfIPCache interface {
	lookup(netip.Addr) (identity.NumericIdentity, error)
	write(netip.Addr, identity.NumericIdentity) error
}

type bpfIPC struct {
	logger *slog.Logger
	sm     *stateManager

	// mapsLock locks access to ipc, start times, and allowWrite
	mapsLock lock.RWMutex
	ipc      *ipcache.Map
	// start time of current and future map
	// used to detect agent reloads
	curStartTime, newStartTime int64
	// whether or not we're allowed to write to the map
	allowWrite bool
}

func newBPFIPCache(logger *slog.Logger, sm *stateManager, config Config, reg *metrics.Registry) bpfIPCache {
	if !config.EnableOfflineMode {
		return nil
	}

	b := &bpfIPC{
		logger: logger,
		sm:     sm,
	}

	sm.addOnUpdate(b.onStateChange)

	// We do care about BPF writes and reads
	metrics.BPFMapOps = metric.NewCounterVec(metric.CounterOpts{
		ConfigName: metrics.Namespace + "_" + metrics.SubsystemBPF + "_map_ops_total",
		Namespace:  metrics.Namespace,
		Subsystem:  metrics.SubsystemBPF,
		Name:       "map_ops_total",
		Help:       "Total operations on map, tagged by map name",
	}, []string{metrics.LabelMapName, metrics.LabelOperation, metrics.LabelOutcome})
	reg.Register(metrics.BPFMapOps)

	return b
}

// syncState manages reopening BPF maps as the agent and proxy
// undergo state transitions.
//
// This is called **synchronously** as part of commits to the state table.
//
// The basic state machine:
//   - Once agent transitions from down to any up state, note it's start time
//   - Once proxy has transitioned to state RPS_LIVE, re-open the bpf map
//     if the start time has changed
func (b *bpfIPC) onStateChange(agent tables.AgentState, proxy tables.RemoteProxyState) {
	b.mapsLock.Lock()
	defer b.mapsLock.Unlock()

	// Did the agent's start time change? Record it, so we can prepare to reopen.
	//
	// We don't re-open immediately, as the proxy continues to write to the "old" BPF map
	// as well as forwarding to the agent until all endpoints have been regenerated.
	//
	// Additionally, handle the case when the map in question has been renamed and thus
	// is not compatible with this version.
	if agent.Status != dnsproxy.AgentStatus_AS_UNSPECIFIED && b.newStartTime != agent.StartTime {
		if agent.IPCacheMapName != ipcache.Name {
			b.logger.Warn("Cannot use IPCache BPF map: agent has incompatible map name (version skew)!",
				logfields.BPFMapName, agent.IPCacheMapName,
				logfields.Want, ipcache.Name)
			b.newStartTime = 0
		} else {
			b.newStartTime = agent.StartTime
		}
	}

	// Only permit writing to the ipcache if the agent is down
	newAllowWrite := (proxy.Status != dnsproxy.RemoteProxyStatus_RPS_LIVE)
	if newAllowWrite != b.allowWrite {
		if newAllowWrite {
			b.logger.Info("Agent is down, enabling BPF IPCache writing")
		} else {
			b.logger.Info("Agent handback is complete, disabling BPF IPCache writing")
		}
		b.allowWrite = newAllowWrite
	}

	// Reload the ipcache if the startTime has changed **and** it has gone live
	if proxy.Status == dnsproxy.RemoteProxyStatus_RPS_LIVE && b.curStartTime != b.newStartTime {
		// Close the previous ipcache handle
		if b.ipc != nil {
			err := b.ipc.Close()
			if err != nil {
				b.logger.Warn("Error closing old BPF IPCache",
					logfields.StartTime, b.curStartTime,
					logfields.Error, err)
			} else {
				b.logger.Info("Closed old BPF IPcache",
					logfields.StartTime, b.curStartTime)
			}
			b.ipc = nil
		}

		// open the new ipcache (if allowed)
		b.curStartTime = b.newStartTime
		if b.curStartTime != 0 {
			b.logger.Info("Proxy is RPS_LIVE, switching to new BPF IPCache map",
				logfields.StartTime, b.newStartTime)
			b.ipc = ipcache.NewMap(nil, ipcache.Name)
			err := b.ipc.Open()
			if err != nil {
				b.logger.Error("Failed to open bpf IPCache map",
					logfields.Error, err,
					logfields.StartTime, b.curStartTime)
				b.ipc = nil
				b.curStartTime = 0
			}
		} else {
			b.logger.Warn("No open bpf IPCache map. Offline mode will not work!")
		}
	}
}

// looks up the identity for a the given IP address from the BPF ipcache map.
func (b *bpfIPC) lookup(addr netip.Addr) (identity.NumericIdentity, error) {
	b.mapsLock.RLock()
	defer b.mapsLock.RUnlock()

	// If we don't have a working ipcache, return.
	if b.ipc == nil {
		return 0, ErrIPCacheInvalid
	}

	b.logger.Debug("BPF ipcache lookup", logfields.Address, addr)

	key := ipcache.NewKey(addr.Unmap().AsSlice(), nil, 0)
	val, err := b.ipc.Lookup(&key)
	if err != nil {
		return identity.NumericIdentity(0), err
	}

	rei, ok := val.(*ipcache.RemoteEndpointInfo)
	if !ok {
		return identity.NumericIdentity(0), fmt.Errorf("could not cast ipcache bpf map value (%[1]T) %[1]v to %T", rei, &ipcache.RemoteEndpointInfo{})
	}
	return identity.NumericIdentity(rei.SecurityIdentity), nil
}

// write writes the IP address to identity mapping to the BPF ipcache map.
func (b *bpfIPC) write(addr netip.Addr, identity identity.NumericIdentity) error {
	b.logger.Debug("BPF ipcache write",
		logfields.Address, addr,
		logfields.Identity, identity,
	)

	b.mapsLock.RLock()
	defer b.mapsLock.RUnlock()
	if b.ipc == nil {
		return ErrIPCacheInvalid
	}
	if !b.allowWrite {
		return ErrWriteDisabled
	}

	key := ipcache.NewKey(addr.Unmap().AsSlice(), nil, 0)
	val := ipcache.RemoteEndpointInfo{
		SecurityIdentity: uint32(identity),
	}
	return b.ipc.Update(&key, &val)
}
