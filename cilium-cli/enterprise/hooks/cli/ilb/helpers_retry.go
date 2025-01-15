//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import (
	"testing"
	"time"
)

// eventually is a helper function that retries a function for given duration
// per tick until it returns nil. If the function doesn't return nil after the
// duration, it calls t.Fatalf against the given t. Otherwise, it returns.
func eventually(t *testing.T, condition func() error, duration time.Duration, waitFor time.Duration) {
	t.Helper()

	ticker := time.NewTicker(waitFor)
	defer ticker.Stop()

	timeout := time.After(duration)

	resultCh := make(chan error)

	var lastErr error
	for tick := ticker.C; ; {
		select {
		case <-tick:
			// Stop the ticker while we are trying
			tick = nil
			go func() {
				resultCh <- condition()
			}()
		case <-timeout:
			t.Fatalf("timeout reached after %s, last error: %v", duration, lastErr)
		case e := <-resultCh:
			if e == nil {
				return
			}
			lastErr = e
			// Reset the ticker after we have received a result
			tick = ticker.C
		}
	}
}
