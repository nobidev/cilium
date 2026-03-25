// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/spf13/pflag"
)

var DefaultConfig = Config{
	EnableVRF: false,
}

type Config struct {
	EnableVRF bool
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-vrf", c.EnableVRF, "Enable virtual routing and forwarding support")
}
