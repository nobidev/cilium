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

package tests

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	daemonCmd "github.com/cilium/cilium/daemon/cmd"
	"github.com/cilium/cilium/enterprise/features"
	operatorCmd "github.com/cilium/cilium/operator/cmd"
	"github.com/cilium/cilium/pkg/hive"
)

// TestValidateFeaturesYAMLFlags validates the flags defined in "features.yaml"
// against the registered flags in the OSS Agent & Operator hives.
//
// We will eventually want to test against the Enterprise hives, but that
// requires being able to import EnterpriseAgent and EnterpriseOperator
// (e.g. enterprise/{daemon,operator} need to be refactored into two packages).
// For the time being the enterprise-specific flag checks are skipped.
//
// This test is in its own package so that 'features' has as few dependencies
// as possible and can be imported into e.g. cilium-cli.
//
// NOTE: Since we're registering flags both via Hive and with InitGlobalFlags
// it may happen that this misses some flags. That's fine though as then the
// test would just fail and you'd need to fix this or the flag registeration
// here to have it covered.
func TestValidateFeaturesYAMLFlags(t *testing.T) {
	log := hivetest.Logger(t)

	mockAgentCmd := &cobra.Command{}
	dh := hive.New(daemonCmd.Agent)
	daemonCmd.InitGlobalFlags(log, mockAgentCmd, dh.Viper())
	dh.RegisterFlags(mockAgentCmd.Flags())

	mockOperatorCmd := &cobra.Command{}
	oh := hive.New(operatorCmd.Operator)
	oh.RegisterFlags(mockOperatorCmd.Flags())
	operatorCmd.InitGlobalFlags(log, mockOperatorCmd, dh.Viper())

	var fs features.YAMLFeatures
	err := yaml.Unmarshal(features.FeaturesYamlContents, &fs)
	require.NoError(t, err)

	for id, f := range fs.Features {
		if id == "Example" {
			continue
		}
		if f.SkipFlagCheck {
			continue
		}

		for key, value := range f.Flags {
			flag := mockAgentCmd.Flags().Lookup(key)
			if flag == nil {
				flag = mockOperatorCmd.Flags().Lookup(key)
			}
			if assert.NotNil(t, flag, "%s: Flag %q not registered to agent or the operator", id, key) {
				if value != "" {
					// A value was provided, can we parse it?
					// This is a rather limited check to see that we're not passing e.g.
					// a number to a bool. It won't catch stuff like 'ipam: foobar'.
					err := flag.Value.Set(value)
					assert.NoError(t, err, "%s: Value %q not valid", id, value)
				}
			}
		}
	}
}
