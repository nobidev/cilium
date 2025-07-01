//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package diagnostics

import (
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/time"
)

var DefaultConfig = Config{
	DiagnosticsInterval:   5 * time.Minute,
	DiagnosticsConstants:  nil,
	DiagnosticsExportFile: "",
}

const (
	DiagnosticsIntervalName   = "diagnostics-interval"
	DiagnosticsConstantsName  = "diagnostics-constants"
	DiagnosticsExportFileName = "diagnostics-export-file"
)

type Config struct {
	// DiagnosticsInterval is the interval at which diagnostic conditions are evaluated
	// and the status written to the status log file.
	DiagnosticsInterval time.Duration `mapstructure:"diagnostics-interval"`

	// DiagnosticsConstants for specifying values for [Environment.UserConstant].
	DiagnosticsConstants map[string]string `mapstructure:"diagnostics-constants"`

	// DiagnosticsExportFile specifies the filepath to write the status events to.
	DiagnosticsExportFile string `mapstructure:"diagnostics-export-file"`
}

var _ cell.Flagger = DefaultConfig

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration(DiagnosticsIntervalName, def.DiagnosticsInterval, "Interval for evaluating diagnostic conditions")
	flags.StringToString(DiagnosticsConstantsName, def.DiagnosticsConstants, "Constant overrides")
	flags.String(DiagnosticsExportFileName, def.DiagnosticsExportFile, "File to which diagnostics events are appended to")
}

func (cfg Config) Validate(knownConstants []string) error {
	var errs error
	for k, v := range cfg.DiagnosticsConstants {
		if !slices.Contains(knownConstants, k) {
			errs = errors.Join(errs, fmt.Errorf("constant %q is not known", k))
		}
		_, err := strconv.ParseFloat(v, 64)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("value %q for constant %q is not a float: %w", v, k, err))
		}
	}
	if errs != nil {
		errs = errors.Join(errs, fmt.Errorf("known constants: %v", knownConstants))
	}
	return errs
}

type Constants map[string]float64

func (cfg Config) GetConstants() map[string]float64 {
	m := map[string]float64{}
	for k, v := range cfg.DiagnosticsConstants {
		f, err := strconv.ParseFloat(v, 64)
		if err == nil {
			m[k] = f
		}
	}
	return m
}
