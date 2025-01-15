// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ilb

import (
	"fmt"
	"os"
)

var testFailed bool

func fatalf(msg string, args ...interface{}) {
	testFailed = true

	fmt.Fprintf(os.Stderr, "\nError: %s\n", fmt.Sprintf(msg, args...))
	RunCleanups()
	os.Exit(1)
}
