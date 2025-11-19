//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package privnet

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"k8s.io/utils/ptr"

	privnet "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// WatchdogMapName is the name of the privnet watchdog map, which is used
	// to detect when the Cilium agent is down for a prolonged period of time.
	WatchdogMapName = "cilium_privnet_watchdog"

	// watchdogEntries is the number of entries in the watchdog map.
	watchdogEntries = 2
)

// getMtime allows overriding bpf.GetMtime for testing purposes.
var getMtime = bpf.GetMtime

// WatchdogIndex is the type of the watchdog map index.
type WatchdogIndex uint32

const (
	// WatchdogIndexLiveness is the index of the map entry used to detect when
	// the Cilium agent is down for a prolonged period of time.
	WatchdogIndexLiveness WatchdogIndex = iota

	// WatchdogIndexTimeout is the index of the map entry storing the timeout
	// for Cilium agent liveness detection.
	WatchdogIndexTimeout
)

func (k *WatchdogIndex) New() bpf.MapKey { return new(WatchdogIndex) }

func (k WatchdogIndex) String() string {
	switch k {
	case WatchdogIndexLiveness:
		return "AgentLiveness"
	case WatchdogIndexTimeout:
		return "AgentLivenessTimeout"
	default:
		return "Unknown"
	}
}

// WatchdogValue is the type of the watchdog map value.
type WatchdogValue uint64

func (v *WatchdogValue) New() bpf.MapValue { return new(WatchdogValue) }

func (v WatchdogValue) String() string {
	return "0x" + strconv.FormatUint(uint64(v), 16)
}

// Watchdog allows to interact with the privnet-watchdog map.
type Watchdog interface {
	// SetAlive updates the map to convey that the Cilium agent is alive.
	SetAlive() error

	// SetTimeout configures the timeout value for Cilium agent liveness.
	SetTimeout(time.Duration) error
}

type watchdog struct {
	enabled bool
	*bpf.Map
}

func newWatchdog(lc cell.Lifecycle, cfg privnet.Config) (bpf.MapOut[Watchdog], defines.NodeOut) {
	wd := watchdog{
		enabled: cfg.Enabled,
		Map: bpf.NewMap(
			WatchdogMapName,
			ebpf.Array,
			ptr.To(WatchdogIndex(0)),
			ptr.To(WatchdogValue(0)),
			watchdogEntries,
			0,
		),
	}

	lc.Append(wd)

	return bpf.NewMapOut(Watchdog(wd)),
		defines.NodeOut{
			NodeDefines: defines.Map{
				"PRIVNET_WATCHDOG_MAP_SIZE": strconv.FormatUint(watchdogEntries, 10),
			},
		}
}

func (w watchdog) SetAlive() error {
	if !w.enabled {
		return errors.New("disabled")
	}

	mtime, err := getMtime()
	if err != nil {
		return fmt.Errorf("getting mtime: %w", err)
	}

	err = w.Map.Update(ptr.To(WatchdogIndexLiveness), ptr.To(WatchdogValue(mtime)))
	if err != nil {
		return fmt.Errorf("updating map: %w", err)
	}

	return nil
}

func (w watchdog) SetTimeout(timeout time.Duration) error {
	if !w.enabled {
		return errors.New("disabled")
	}

	err := w.Map.Update(ptr.To(WatchdogIndexTimeout), ptr.To(WatchdogValue(timeout.Nanoseconds())))
	if err != nil {
		return fmt.Errorf("updating map: %w", err)
	}

	return nil
}

func (w watchdog) Start(cell.HookContext) error {
	if !w.enabled {
		err := w.Map.Unpin()
		if err != nil {
			return fmt.Errorf("unpinning privnet-watchdog map: %w", err)
		}
		return nil
	}

	err := w.Map.Recreate()
	if err != nil {
		return fmt.Errorf("recreating privnet-watchdog map: %w", err)
	}
	return nil
}

func (w watchdog) Stop(cell.HookContext) error {
	if !w.enabled {
		return nil
	}

	err := w.Map.Close()
	if err != nil {
		return fmt.Errorf("closing privnet-watchdog map: %w", err)
	}

	return nil
}
