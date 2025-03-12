//nolint:goheader
// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package features

import "github.com/spf13/pflag"

var defaultFeatureGatesConfig = FeatureGatesConfig{
	ApprovedFeatures: []string{},

	// The default minimum maturity is the 1st maturity level, i.e. Stable.
	MinimumMaturity: FeaturesYaml.Levels[0].Name,

	// Enable strict feature gate checking.
	StrictFeatureGates: true,
}

// FeatureGateConfig is the configuration for the feature gates.
type FeatureGatesConfig struct {
	ApprovedFeatures   []string `mapstructure:"feature-gates-approved"`
	MinimumMaturity    string   `mapstructure:"feature-gates-minimum-maturity"`
	StrictFeatureGates bool     `mapstructure:"feature-gates-strict"`
}

const (
	FeatureGatesApprovedFlag        = "feature-gates-approved"
	FeatureGatesMinimumMaturityFlag = "feature-gates-minimum-maturity"
	FeatureGatesStrictFlag          = "feature-gates-strict"
)

func (c FeatureGatesConfig) Flags(flags *pflag.FlagSet) {
	flags.StringSlice(FeatureGatesApprovedFlag, c.ApprovedFeatures, "Features approved to be enabled regardless of maturity level")
	flags.String(FeatureGatesMinimumMaturityFlag, c.MinimumMaturity, "Minimum feature maturity level to approve a feature")
	flags.Bool(FeatureGatesStrictFlag, c.StrictFeatureGates, "If enabled agent will refuse to start if feature gates do not pass")
}
