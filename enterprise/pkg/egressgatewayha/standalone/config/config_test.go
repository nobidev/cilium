//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/healthconfig"
	"github.com/cilium/cilium/pkg/option"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		dcfg      func(*option.DaemonConfig)
		healthCfg healthconfig.Config
		assertion func(t assert.TestingT, err error, msgAndArgs ...any) bool
	}{
		{
			name: "segw enabled",
			cfg: Config{
				EnableIPv4StandaloneEgressGateway: true,
				StandaloneEgressGatewayInterface:  "",
			},
			dcfg:      func(dcfg *option.DaemonConfig) {},
			healthCfg: healthconfig.Config{EnableHealthChecking: true},
			assertion: assert.NoError,
		},
		{
			name: "segw disabled, egw-ha enabled",
			cfg: Config{
				EnableIPv4StandaloneEgressGateway: false,
				StandaloneEgressGatewayInterface:  "",
			},
			dcfg:      func(dcfg *option.DaemonConfig) { dcfg.EnableIPv4EgressGatewayHA = true },
			healthCfg: healthconfig.Config{EnableHealthChecking: true},
			assertion: assert.NoError,
		},
		{
			name: "segw enabled, egw-ha enabled",
			cfg: Config{
				EnableIPv4StandaloneEgressGateway: true,
				StandaloneEgressGatewayInterface:  "",
			},
			dcfg:      func(dcfg *option.DaemonConfig) { dcfg.EnableIPv4EgressGatewayHA = true },
			healthCfg: healthconfig.Config{EnableHealthChecking: true},
			assertion: assert.Error,
		},
		{
			name: "segw enabled, masquerade disabled",
			cfg: Config{
				EnableIPv4StandaloneEgressGateway: true,
				StandaloneEgressGatewayInterface:  "",
			},
			dcfg:      func(dcfg *option.DaemonConfig) { dcfg.EnableBPFMasquerade = false },
			healthCfg: healthconfig.Config{EnableHealthChecking: true},
			assertion: assert.Error,
		},
		{
			name: "segw enabled, health checking disabled",
			cfg: Config{
				EnableIPv4StandaloneEgressGateway: true,
				StandaloneEgressGatewayInterface:  "",
			},
			dcfg:      func(dcfg *option.DaemonConfig) {},
			healthCfg: healthconfig.Config{EnableHealthChecking: false},
			assertion: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dcfg := option.DaemonConfig{
				EnableIPv4Masquerade: true,
				EnableBPFMasquerade:  true,
			}

			tt.dcfg(&dcfg)
			tt.assertion(t, tt.cfg.Validate(&dcfg, tt.healthCfg))
		})
	}
}
