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
	"errors"
	"testing"
	"testing/synctest"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/maps/privnet"
	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

type wdmap struct {
	mu lock.RWMutex

	alive   time.Time
	timeout time.Duration

	aliveErr, timeoutErr error
}

func (f *wdmap) SetAlive() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.aliveErr == nil {
		f.alive = time.Now()
	}

	return f.aliveErr
}

func (f *wdmap) SetTimeout(timeout time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.timeoutErr == nil {
		f.timeout = timeout
	}

	return f.timeoutErr
}

func (f *wdmap) setErrors(alive, timeout error) {
	f.mu.Lock()
	f.aliveErr = alive
	f.timeoutErr = timeout
	f.mu.Unlock()
}

func fixture(t *testing.T, override time.Duration) (*watchdog, *wdmap) {
	var (
		log = hivetest.Logger(t)

		wd  *watchdog
		wdm wdmap
	)

	h := hive.New(
		Cell,

		cell.Provide(
			func() config.Config {
				return config.Config{
					Common: config.Common{Enabled: true},
				}
			},
			func() privnet.Watchdog { return &wdm },
		),

		cell.Invoke(
			func(wd_ Watchdog) { wd = wd_.(*watchdog) },
		),
	)

	if override != 0 {
		hive.AddConfigOverride(h, func(c *Config) { c.Timeout = override })
	}

	require.NoError(t, h.Start(log, t.Context()), "hive.Start")
	t.Cleanup(func() {
		require.NoError(t, h.Stop(log, context.Background()), "hive.Stop")
	})

	return wd, &wdm
}

func check(t *testing.T, wdm *wdmap, alive time.Time, timeout time.Duration, msgAndArgs ...any) {
	synctest.Wait()

	wdm.mu.RLock()
	require.Equal(t, alive, wdm.alive, msgAndArgs...)
	require.Equal(t, timeout, wdm.timeout, msgAndArgs...)
	wdm.mu.RUnlock()
}

func TestWatchdogWithoutOverride(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		wd, wdm := fixture(t, 0)

		// By default, it should respect the default timeout.
		time.Sleep(defaultTimeout / 5)
		check(t, wdm, time.Now(), defaultTimeout)

		for _, requested := range []time.Duration{
			defaultTimeout / 2, 0, defaultTimeout * 2, defaultTimeout,
		} {
			wd.RequestTimeout("__foo__", requested)

			var (
				timeout  = cmp.Or(requested, defaultTimeout)
				interval = timeout / 5
				expected = time.Now()
			)

			check(t, wdm, expected, timeout, "Requested timeout: %v", requested)

			// No update should have occurred before interval.
			time.Sleep(interval - 1*time.Microsecond)
			check(t, wdm, expected, timeout, "Requested timeout: %v", requested)

			// Setting the same timeout should not trigger an update.
			wd.RequestTimeout("__foo__", requested)
			check(t, wdm, expected, timeout, "Requested timeout: %v", requested)

			// Liveness should be updated every interval
			time.Sleep(100 * time.Microsecond)
			expected = expected.Add(interval)
			check(t, wdm, expected, timeout, "Requested timeout: %v", requested)

			for i := range 5 {
				time.Sleep(interval)
				expected = expected.Add(interval)
				check(t, wdm, expected, timeout, "Requested timeout: %v, Iteration: %v", requested, i)
			}
		}

		// A timeout update error should be retried.
		wdm.setErrors(nil, errors.New("failing on purpose"))
		wd.RequestTimeout("__foo__", defaultTimeout*5)
		time.Sleep(300 * time.Millisecond /* two retries */)
		check(t, wdm, time.Now(), defaultTimeout)

		wdm.setErrors(nil, nil)
		time.Sleep(400 * time.Millisecond)
		check(t, wdm, time.Now(), defaultTimeout*5)

		// Assert that the interval is still correct.
		var expected = time.Now()
		time.Sleep(defaultTimeout - 1*time.Microsecond)
		check(t, wdm, expected, defaultTimeout*5)
		time.Sleep(100 * time.Millisecond)
		check(t, wdm, expected.Add(defaultTimeout), defaultTimeout*5)
	})
}

func TestWatchdogWithOverride(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			interval = 200 * time.Millisecond
			timeout  = 1 * time.Second
		)

		var (
			wd, wdm  = fixture(t, timeout)
			expected = time.Now()
		)

		check(t, wdm, expected, timeout)

		// No update should have occurred before interval.
		time.Sleep(interval - 1*time.Microsecond)
		check(t, wdm, expected, timeout)

		// Setting a timeout should not trigger a map update.
		wd.RequestTimeout("__foo__", 1*time.Millisecond)
		check(t, wdm, expected, timeout)

		// Liveness should be updated every interval.
		time.Sleep(100 * time.Microsecond)
		expected = expected.Add(interval)
		check(t, wdm, expected, timeout)

		for i := range 5 {
			time.Sleep(interval)
			expected = expected.Add(interval)
			check(t, wdm, expected, timeout, "Iteration: %v", i)
		}

		// An update error should be retried.
		wdm.setErrors(errors.New("failing on purpose"), nil)
		time.Sleep(interval + 300*time.Millisecond /* two retries */)
		check(t, wdm, expected, timeout)

		wdm.setErrors(nil, nil)
		time.Sleep(400 * time.Millisecond)
		check(t, wdm, expected.Add(interval+700*time.Millisecond), timeout)
	})
}

func TestWatchdogRequestRelease(t *testing.T) {
	tests := []struct {
		id       string
		timeout  time.Duration
		expected time.Duration
		updated  bool
	}{
		// Consecutive updates with the same ID.
		{"foo", 2 * time.Second, 2 * time.Second, true},
		{"foo", 4 * time.Second, 4 * time.Second, true},
		{"foo", 4 * time.Second, 4 * time.Second, false},
		{"foo", 1 * time.Second, 1 * time.Second, true},
		{"foo", 0 * time.Second, defaultTimeout, true},

		// Mixed updates with different IDs
		{"foo", 2 * time.Second, 2 * time.Second, true},  // foo: 2
		{"bar", 4 * time.Second, 2 * time.Second, false}, // foo: 2, bar: 4
		{"baz", 1 * time.Second, 1 * time.Second, true},  // foo: 2, bar: 4, baz: 1
		{"qux", 3 * time.Second, 1 * time.Second, false}, // foo: 2, bar: 4, baz: 1, qux: 3
		{"baz", 3 * time.Second, 2 * time.Second, true},  // foo: 2, bar: 4, baz: 3, qux: 3
		{"qux", 1 * time.Second, 1 * time.Second, true},  // foo: 2, bar: 4, baz: 3, qux: 1
		{"qux", 0 * time.Second, 2 * time.Second, true},  // foo: 2, bar: 4, baz: 3
		{"baz", 4 * time.Second, 2 * time.Second, false}, // foo: 2, bar: 4, baz: 4
		{"foo", 5 * time.Second, 4 * time.Second, true},  // foo: 5, bar: 4, baz: 4
		{"bar", 0 * time.Second, 4 * time.Second, false}, // foo: 5, baz: 4
		{"baz", 0 * time.Second, 5 * time.Second, true},  // foo: 5
		{"foo", 2 * time.Second, 2 * time.Second, true},  // foo: 2
		{"foo", 0 * time.Second, defaultTimeout, true},
	}

	synctest.Test(t, func(t *testing.T) {
		var (
			wd, wdm = fixture(t, 0)
			alive   time.Time
		)

		for i, tt := range tests {
			// Slowly advance time, so that we can check whether an update got
			// triggered or not.
			time.Sleep(1 * time.Microsecond)

			if tt.timeout > 0 {
				wd.RequestTimeout(tt.id, tt.timeout)
			} else {
				wd.ReleaseTimeout(tt.id)
			}

			if tt.updated {
				alive = time.Now()
			}

			check(t, wdm, alive, tt.expected, "[%d] %v", i, tt)
		}
	})
}
