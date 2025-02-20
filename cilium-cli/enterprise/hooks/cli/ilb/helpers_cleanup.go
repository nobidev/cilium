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
	"fmt"
	"slices"
)

var cleanupCb = []func(){}

// RegisterMaybeCleanupAfterTest registers a function to be called when the test complete.
// Cleanup functions will be executed if cleanup functionality is enabled and
// will called in last added, first called order.
func RegisterMaybeCleanupAfterTest(f func() error) {
	if FlagCleanup {
		cleanupCb = append(cleanupCb, func() {
			if err := f(); err != nil {
				fmt.Printf("cleanup failed %s\n", err)
			}
		})
	}
}

// MaybeCleanupNow immediately tries to execute the given function function if cleanup functionality is enabled.
func MaybeCleanupNow(f func() error) {
	if FlagCleanup {
		if err := f(); err != nil {
			fmt.Printf("cleanup failed: %s\n", err)
		}
	}
}

func RunCleanups() {
	for _, f := range slices.Backward(cleanupCb) {
		f()
	}

	cleanupCb = []func(){}
}
