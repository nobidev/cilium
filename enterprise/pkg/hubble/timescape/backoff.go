// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package timescape

import (
	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/time"
)

// Backoff defines an interface for calculating backoff durations based on the number of attempts.
type Backoff interface {
	Duration(attempt int) time.Duration
}

// exponentialBackoff returns a backoff implementation that uses an exponential backoff strategy.
func exponentialBackoff() Backoff {
	return &backoff.Exponential{
		Min:    time.Second,
		Max:    time.Minute,
		Factor: 2.0,
	}
}
