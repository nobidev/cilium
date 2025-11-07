// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// slogloggercheck: reintroduce here as cannot access 'log' in cilium-dbg/cmd.
var log = logging.DefaultSlogLogger.With(logfields.LogSubsys, "cilium-dbg")

// Fatalf prints the Printf formatted message to stderr and exits the program
// Note: os.Exit(1) is not recoverable
func Fatalf(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", fmt.Sprintf(msg, args...))
	os.Exit(1)
}
