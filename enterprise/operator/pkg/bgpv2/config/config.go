// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package config

import (
	"github.com/spf13/pflag"
)

const (
	// EnterpriseBGPEnabled is the name of the flag to enable the BGP control plane.
	EnterpriseBGPEnabled = "enable-enterprise-bgp-control-plane"
	// EnterpriseBGPStatusReportEnabled is the name of the flag to enable the BGP control plane status report.
	EnterpriseBGPStatusReportEnabled = "enable-enterprise-bgp-control-plane-status-report"
)

// Config parameters for enterprise BGP.
type Config struct {
	Enabled             bool `mapstructure:"enable-enterprise-bgp-control-plane"`
	StatusReportEnabled bool `mapstructure:"enable-enterprise-bgp-control-plane-status-report"`
}

// Flags implements cell.Flagger interface.
func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnterpriseBGPEnabled, cfg.Enabled, "Enable enterprise BGP in Cilium")
	flags.Bool(EnterpriseBGPStatusReportEnabled, cfg.StatusReportEnabled, "Enable enterprise BGP status report in Cilium")
}

var DefaultConfig = Config{
	Enabled:             false,
	StatusReportEnabled: true,
}
