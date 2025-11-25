//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import (
	"context"
	"flag"
	"log/slog"
	"maps"
	"net"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pnmaps "github.com/cilium/cilium/enterprise/pkg/maps/privnet"
	pncfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc"
	"github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/server"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/testutils"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

func TestScript(t *testing.T) {
	defer testutils.GoleakVerifyNone(t)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)

	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			var opts []hivetest.LogOption
			if *debug {
				opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
				logging.SetLogLevelToDebug()
			}
			log := hivetest.Logger(t, opts...)

			h := hive.New(
				pncfg.Cell,
				grpc.Cell,

				ConnFactoryCell(t.TempDir()),
				ServerPoolCell,
				CheckerPoolCell,

				cell.Group(
					cell.Provide(
						tables.NewPrivateNetworksTable,
						statedb.RWTable[tables.PrivateNetwork].ToTable,
						func() pnmaps.Watchdog { return watchdog{} },
					),

					cell.DecorateAll(
						func(cf ConnFactory) server.ListenerFactory {
							return func(context.Context) ([]net.Listener, error) {
								lis, err := cf.NewListener(Instance{Cluster: "local", Name: "sloth"})
								return []net.Listener{lis}, err
							}
						},
					),
				),
			)

			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.Background()))
			})

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)

			require.NoError(t, flags.Parse(args), "flags.Parse")

			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))

			return &script.Engine{
				Cmds:          cmds,
				RetryInterval: 10 * time.Millisecond,
			}
		}, []string{}, "testdata/*.txtar")
}

type watchdog struct{}

func (w watchdog) SetAlive() error                { return nil }
func (w watchdog) SetTimeout(time.Duration) error { return nil }
