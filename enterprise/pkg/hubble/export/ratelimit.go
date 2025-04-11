// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package export

import (
	"context"
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/exporter"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

const rateLimitInterval = 1 * time.Minute

var _ exporter.OnExportEvent = (*enterpriseRateLimiter)(nil)

type enterpriseRateLimiter struct {
	ratelimiter *rateLimiter
}

func newRateLimiterFromStaticConfig(conf config, logger logrus.FieldLogger) (*enterpriseRateLimiter, error) {
	ratelimiter, err := NewRateLimiter(conf.RateLimit, rateLimitInterval, conf.NodeName, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create static flow export rate limiter: %w", err)
	}
	return &enterpriseRateLimiter{ratelimiter: ratelimiter}, nil
}

func newRateLimiterFromDynamicConfig(conf *EnterpriseFlowLogConfig, logger logrus.FieldLogger) (*enterpriseRateLimiter, error) {
	rateLimit := -1
	if conf.RateLimit != nil {
		rateLimit = *conf.RateLimit
	}
	ratelimiter, err := NewRateLimiter(rateLimit, rateLimitInterval, conf.NodeName, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic flow export rate limiter: %w", err)
	}
	return &enterpriseRateLimiter{ratelimiter: ratelimiter}, nil
}

// OnExportEvent implements the exporter.OnExportEvent interface.
func (e *enterpriseRateLimiter) OnExportEvent(ctx context.Context, ev *v1.Event, encoder exporter.Encoder) (stop bool, err error) {
	return e.ratelimiter.Enforce(encoder), nil
}

// RateLimitInfoEvent is an event that is emitted by rateLimiter.Enforce().
type RateLimitInfoEvent struct {
	RateLimitInfo *RateLimitInfo `json:"rate_limit_info"`
	NodeName      string         `json:"node_name"`
	Time          time.Time      `json:"time"`
}

// RateLimitInfo provides the number of dropped events.
type RateLimitInfo struct {
	NumberOfDroppedEvents uint64 `json:"number_of_dropped_events"`
}

// rateLimiter controls how frequently events are allowed to happen.
type rateLimiter struct {
	limiter *rate.Limiter

	logger           logrus.FieldLogger
	nodeName         string
	throttleInterval time.Duration

	// used to mock time in tests
	curTime func() time.Time

	lastReport time.Time
	dropped    uint64
}

// NewRateLimiter returns a rateLimiter instance.
func NewRateLimiter(numEvents int, interval time.Duration, nodeName string, logger logrus.FieldLogger) (*rateLimiter, error) {
	if numEvents < 0 {
		return nil, errors.New("numEvents cannot be negative")
	}
	r := &rateLimiter{
		limiter:          rate.NewLimiter(getLimit(numEvents, interval), numEvents),
		logger:           logger,
		nodeName:         nodeTypes.GetName(), // TODO(tk): use nodeTypes.GetAbsoluteNodeName() once we switch to Cilium 1.10.
		throttleInterval: interval,
		curTime:          func() time.Time { return time.Now() },
	}
	if nodeName != "" {
		r.nodeName = nodeName
	}
	return r, nil
}

// Enforce implements the RateLimiter interface.
//
// It returns true if we should enforce rate-limiting. It emits RateLimitInfoEvent using the
// provided encoder at minimum throttleInterval if the internal counter is non-zero, and then resets
// the counter.
func (r *rateLimiter) Enforce(encoder exporter.Encoder) bool {
	enforced := !r.limiter.Allow()
	if enforced {
		r.dropped += 1
		r.logger.WithField("dropped", r.dropped).Debug("rate limited")
	}
	now := r.curTime()
	if now.Sub(r.lastReport) > r.throttleInterval && r.dropped > 0 {
		r.lastReport = now
		r.report(encoder)
		r.dropped = 0
	}
	return enforced
}

// report writes json-encoded RateLimitInfoEvent to the provided encoder.
func (r *rateLimiter) report(encoder exporter.Encoder) {
	err := encoder.Encode(&RateLimitInfoEvent{
		RateLimitInfo: &RateLimitInfo{NumberOfDroppedEvents: r.dropped},
		NodeName:      r.nodeName,
		Time:          r.lastReport,
	})
	if err != nil {
		r.logger.WithError(err).WithField("dropped", r.dropped).Warn("Failed to encode RateLimitInfoEvent event")
	}
}

// getLimit converts an numEvents and interval to rate.Limit which is a floating point value
// representing number of events per second.
func getLimit(numEvents int, interval time.Duration) rate.Limit {
	if numEvents == 0 {
		return 0
	}
	return rate.Every(interval / time.Duration(numEvents))
}
