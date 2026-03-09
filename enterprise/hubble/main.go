// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package main

import (
	"github.com/cilium/cilium/enterprise/hubble/cmd"

	// Register API extensions
	_ "github.com/cilium/cilium/enterprise/pkg/hubble/apis/extensions"
)

func main() {
	cmd.Execute()
}
