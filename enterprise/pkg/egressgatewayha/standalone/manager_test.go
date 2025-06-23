//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package standalone

import (
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	segwcfg "github.com/cilium/cilium/enterprise/pkg/egressgatewayha/standalone/config"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
)

func TestDatapathConfigProvider(t *testing.T) {
	tests := []struct {
		name string
		cfg  segwcfg.Config

		assertTunnelEnabled assert.BoolAssertionFunc
		assertDefines       assert.ComparisonAssertionFunc
	}{
		{
			name: "segw disabled",
			cfg: segwcfg.Config{
				EnableIPv4StandaloneEgressGateway: false,
				StandaloneEgressGatewayInterface:  "",
			},
			assertTunnelEnabled: assert.False,
			assertDefines:       assert.NotContains,
		},
		{
			name: "segw enabled",
			cfg: segwcfg.Config{
				EnableIPv4StandaloneEgressGateway: true,
				StandaloneEgressGatewayInterface:  "",
			},
			assertTunnelEnabled: assert.True,
			assertDefines:       assert.Contains,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				outProto tunnel.EncapProtocol
				outDef   = defines.Map{}
			)

			require.NoError(t, hive.New(cell.Group(
				tunnel.Cell,

				cell.Provide(
					datapathConfigProvider,
					func() segwcfg.Config { return tt.cfg },
					func() *option.DaemonConfig {
						return &option.DaemonConfig{
							RoutingMode: option.RoutingModeNative,
						}
					},
					func() loadbalancer.Config {
						return loadbalancer.DefaultConfig
					},
					func() kpr.KPRConfig { return kpr.KPRConfig{} },
				),

				cell.Invoke(func(in struct {
					cell.In
					Tunnel           tunnel.Config
					NodeExtraDefines []defines.Map `group:"header-node-defines"`
				}) {
					outProto = in.Tunnel.EncapProtocol()
					for _, ned := range in.NodeExtraDefines {
						outDef.Merge(ned)
					}
				}),
			)).Populate(hivetest.Logger(t)))

			tt.assertTunnelEnabled(t, outProto != tunnel.Disabled)
			tt.assertDefines(t, outDef, "ENABLE_EGRESS_GATEWAY_HA")
			tt.assertDefines(t, outDef, "ENABLE_EGRESS_GATEWAY_STANDALONE")
		})
	}
}
