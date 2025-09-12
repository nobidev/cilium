// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthcheck

import (
	"log/slog"

	probing "github.com/prometheus-community/pro-bing"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

const (
	probeInterval    = 100 * time.Millisecond
	failureThreshold = 3
)

type icmpProber struct {
	logger  *slog.Logger
	ip      string
	timeout time.Duration
}

func (i *icmpProber) runHealthcheckProbe() bool {
	result := false
	pinger, err := probing.NewPinger(i.ip)
	if err != nil {
		i.logger.Error("Failed to create pinger", logfields.Error, err)
		return false
	}

	pinger.Timeout = i.timeout
	pinger.Count = failureThreshold
	pinger.Interval = probeInterval
	pinger.OnRecv = func(pkt *probing.Packet) {
		pinger.Stop()
	}
	pinger.OnFinish = func(stats *probing.Statistics) {
		if stats.PacketsRecv > 0 && len(stats.Rtts) > 0 {
			result = true
		} else {
			result = false
		}
	}
	pinger.SetPrivileged(true)
	err = pinger.Run()
	if err != nil {
		i.logger.Error("Failed to run pinger for IP",
			logfields.IPAddr, i.ip,
			logfields.Error, err,
		)
		return false
	}

	return result
}

func (i *icmpProber) mode() probeMode {
	return ICMP
}
