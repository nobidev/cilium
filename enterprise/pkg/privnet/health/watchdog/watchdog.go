//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package watchdog

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/enterprise/pkg/maps/privnet"
	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	Cell = cell.Group(
		cell.Config(defaultConfig),
		cell.Provide(newWatchdog),
		cell.Invoke(func(Watchdog) { /* force instantiation */ }),
	)

	defaultConfig = Config{
		// By default (i.e., Timeout=0), the INB computes the timeout based on
		// the interval and timeout information propagated by the workload nodes,
		// but can be overwritten via the dedicated flag.
		Timeout: 0,
	}
)

// defaultTimeout is the default timeout used when not explicitly overridden,
// either via the dedicated flag or through the [Watchdog] interface.
const defaultTimeout = 2 * time.Second

type Config struct {
	// Timeout is the timeout after which the datapath stops performing L2 announcements
	// towards the external networks if the Cilium agent is down.
	Timeout time.Duration `mapstructure:"private-networks-agent-liveness-timeout"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("private-networks-agent-liveness-timeout", def.Timeout,
		"Override the timeout to detect that the Cilium agent is down, and stop performing L2 announcements towards the external network")
	flags.MarkHidden("private-networks-agent-liveness-timeout")
}

// Watchdog enables configuring the timeout used by the agent liveness watchdog.
// Multiple components can request a watchdog timeout; the lowest requested value
// is the one that gets used. Requests and releases for the same component are
// correlated via the provided ID.
type Watchdog interface {
	// RequestTimeout requests a timeout value, associated with a given component.
	RequestTimeout(id string, timeout time.Duration)

	// ReleaseTimeout releases the timeout previously requested by the component.
	ReleaseTimeout(id string)
}

type watchdog struct {
	log   *slog.Logger
	wdmap privnet.Watchdog

	mu      lock.RWMutex
	timeout time.Duration
	tracker map[string]time.Duration

	updated    chan struct{}
	overridden bool
}

func newWatchdog(
	jg job.Group, log *slog.Logger,
	wdmap privnet.Watchdog,
	cfg config.Config, wdcfg Config,
) Watchdog {
	wd := &watchdog{
		log:   log,
		wdmap: wdmap,

		timeout:    wdcfg.Timeout,
		updated:    make(chan struct{}, 1),
		overridden: wdcfg.Timeout != 0,

		tracker: make(map[string]time.Duration),
	}

	if !cfg.Enabled {
		return wd
	}

	jg.Add(
		job.OneShot(
			"watchdog-liveness", wd.run,
			job.WithRetry(-1, &job.ExponentialBackoff{
				Min: 100 * time.Millisecond, Max: 1 * time.Second},
			),
		),
	)

	return wd
}

func (w *watchdog) RequestTimeout(id string, timeout time.Duration) {
	if w.overridden {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	prev, ok := w.tracker[id]
	if timeout > 0 {
		w.tracker[id] = timeout
	} else {
		delete(w.tracker, id)
	}

	// We are guaranteed that the selected timeout does not change if:
	// * The requested value for the given ID matches the one previously requested;
	// * This is the first time we see the ID, and the requested value is not
	//   lower than the currently selected timeout;
	// * The given ID is being released, and the requested value was higher than
	//   the currently selected timeout;
	if prev == timeout ||
		(!ok && w.timeout > 0 && timeout >= w.timeout) ||
		(timeout == 0 && prev > w.timeout) {
		return
	}

	for _, val := range w.tracker {
		if timeout == 0 {
			timeout = val
		} else {
			timeout = min(timeout, val)
		}
	}

	if w.timeout == timeout {
		return
	}

	w.timeout = timeout

	select {
	case w.updated <- struct{}{}:
	default:
	}
}

func (w *watchdog) ReleaseTimeout(id string) {
	w.RequestTimeout(id, 0)
}

func (w *watchdog) getTimeout() time.Duration {
	w.mu.RLock()
	defer w.mu.RUnlock()

	return cmp.Or(w.timeout, defaultTimeout)
}

func (w *watchdog) run(ctx context.Context, health cell.Health) error {
	const intervalFactor = 5

	var (
		updated = true
		timeout = w.getTimeout()
		ticker  = time.NewTicker(timeout / intervalFactor)
	)

	for {
		err := w.wdmap.SetAlive()
		if err != nil {
			return fmt.Errorf("setting liveness: %w", err)
		}

		if updated {
			err = w.wdmap.SetTimeout(timeout)
			if err != nil {
				return fmt.Errorf("setting timeout: %w", err)
			}

			updated = false
			ticker.Reset(timeout / intervalFactor)
			health.OK(fmt.Sprintf("Watchdog timeout is %s", timeout))
			w.log.Info("Watchdog timeout updated", logfields.Timeout, timeout)
		}

		select {
		case <-ticker.C:
		case <-w.updated:
			timeout = w.getTimeout()
			updated = true
		case <-ctx.Done():
			ticker.Stop()
			return nil
		}
	}
}
