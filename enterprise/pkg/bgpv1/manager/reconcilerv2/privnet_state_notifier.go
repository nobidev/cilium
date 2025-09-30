// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/evpn"
	pnCfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/manager"
)

type privnetStatusNotifierIn struct {
	cell.In

	Logger *slog.Logger

	Config        config.Config
	EVPNConfig    evpn.Config
	PrivnetConfig pnCfg.Config

	JG            job.Group
	DB            *statedb.DB
	Table         statedb.Table[tables.PrivateNetwork]
	RouterManager agent.BGPRouterManager
}

func registerPrivnetStatusNotifier(in privnetStatusNotifierIn) {
	if !in.Config.Enabled || !in.EVPNConfig.Enabled || !in.PrivnetConfig.Enabled {
		return
	}

	// This is needed for mindfullness. To avoid this dirty hack, we would
	// need to modify OSS NewBGPRouterManager to return the concrete type.
	rm, ok := in.RouterManager.(*manager.BGPRouterManager)
	if !ok {
		in.Logger.Error("Failed to cast RouterManager to concrete type")
		return
	}

	in.JG.Add(job.OneShot("privnet-status-notifier", func(ctx context.Context, health cell.Health) error {
		rtxn := in.DB.ReadTxn()

		health.OK("Waiting for private-networks table initialization")

		_, watch := in.Table.Initialized(rtxn)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-watch:
		}

		for {
			rtxn := in.DB.ReadTxn()

			// We don't care about the actual changes, we just need
			// to be notified for any change.
			_, watch := in.Table.AllWatch(rtxn)

			rm.Lock()
			for _, instance := range rm.BGPInstances {
				instance.NotifyStateChange()
			}
			rm.Unlock()

			health.OK("Status change notified")

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-watch:
			}
		}
	}))
}
