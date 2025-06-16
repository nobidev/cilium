//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	"context"
	"maps"
	"testing"

	hiveExt "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha/healthcheck"
	operatorK8s "github.com/cilium/cilium/operator/k8s"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/hive"
	k8sFake "github.com/cilium/cilium/pkg/k8s/client/testutils"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

func TestOperatorScripts(t *testing.T) {
	log := hivetest.Logger(t)
	ctx := t.Context()

	// Set the node name to be "localnode1" for all the tests.
	nodeTypes.SetName("localnode1")

	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			h := hive.New(
				OperatorCell,
				PolicyCell,
				k8sFake.FakeClientCell(),
				operatorK8s.ResourcesCell,
				cell.Provide(func() healthcheck.Healthchecker {
					return &mockHealthChecker{}
				}),
				cell.Provide(
					func() *operatorOption.OperatorConfig {
						return operatorOption.Config
					},
					func() *option.DaemonConfig {
						return &option.DaemonConfig{
							EnterpriseDaemonConfig: option.EnterpriseDaemonConfig{
								EnableIPv4EgressGatewayHA: true,
							},
							EnableBPFMasquerade:    true,
							EnableIPv4Masquerade:   true,
							IdentityAllocationMode: option.IdentityAllocationModeCRD,
							EnableHealthChecking:   true,
							Debug:                  false,
						}
					},
				),

				cell.Invoke(func(*OperatorManager, hiveExt.ScriptCmds) {}),
			)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)

			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.TODO()))
			})
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))
			return &script.Engine{
				Cmds:          cmds,
				RetryInterval: 1500 * time.Millisecond,
			}
		}, []string{}, "testdata/operator_*.txtar")
}

type mockHealthChecker struct{}

func (m *mockHealthChecker) UpdateNodeList(nodes map[string]nodeTypes.Node, healthy sets.Set[string], probeModeByNode map[string]healthcheck.ProbeMode) {
}
func (m *mockHealthChecker) NodeIsHealthy(nodeName string) bool {
	return true
}
func (m *mockHealthChecker) Events() chan healthcheck.Event {
	ch := make(chan healthcheck.Event)
	return ch
}
func (m *mockHealthChecker) SetProber(node nodeTypes.Node, mode healthcheck.ProbeMode) bool {
	return false
}
