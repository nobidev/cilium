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
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	segwcfg "github.com/cilium/cilium/enterprise/pkg/egressgatewayha/standalone/config"
	"github.com/cilium/cilium/enterprise/pkg/maps/egressmapha"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/linux/netdevice"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
)

var Cell = cell.Module(
	"standalone-egressgateway",
	"Egress Gateway on standalone VMs",

	cell.Config(segwcfg.Config{
		EnableIPv4StandaloneEgressGateway: false,
		StandaloneEgressGatewayInterface:  "",
	}),

	cell.Provide(
		// Configure the datapath to enable the configuration fo the tunnel device
		// and the compilation of the appropriate logic when SEGW is enabled.
		datapathConfigProvider,
	),

	cell.Invoke(
		// Validate the SEGW configuration.
		segwcfg.Config.Validate,

		// Register the job to perform sanity checks and configure the default
		// egress gateway policy matching all traffic exiting the tunnel.
		registerJobs,
	),
)

func datapathConfigProvider(cfg segwcfg.Config) (out struct {
	cell.Out
	defines.NodeOut
	tunnel.EnablerOut
}) {
	if !cfg.EnableIPv4StandaloneEgressGateway {
		return out
	}

	out.NodeDefines = map[string]string{
		"ENABLE_EGRESS_GATEWAY_HA":         "1",
		"ENABLE_EGRESS_GATEWAY_STANDALONE": "1",
	}
	out.EnablerOut = tunnel.NewEnabler(true)
	return out
}

type params struct {
	cell.In

	Logger *slog.Logger

	Config    segwcfg.Config
	PolicyMap egressmapha.PolicyMapV2

	Lifecycle cell.Lifecycle
	JobGroup  job.Group
	Log       *slog.Logger
}

func registerJobs(p params) {
	if !p.Config.EnableIPv4StandaloneEgressGateway {
		return
	}

	p.JobGroup.Add(
		job.OneShot("standalone-egress-gateway-setup",
			asyncSetup(p.Logger, p.PolicyMap, p.Config.StandaloneEgressGatewayInterface),
			job.WithShutdown(),
		),
	)
}

func asyncSetup(logger *slog.Logger, pm egressmapha.PolicyMapV2, ifaceName string) job.OneShotFunc {
	return func(_ context.Context, _ cell.Health) error {
		if ifaceName == "" {
			// If the user did not explicitly configure an interface, use
			// the one with the IPv4 default route.
			iface, err := route.NodeDeviceWithDefaultRoute(logger, true, false)
			if err != nil {
				return fmt.Errorf("failed to find interface with default route: %w", err)
			}

			ifaceName = iface.Attrs().Name
		}

		egressIP, err := netdevice.GetIfaceFirstIPv4Address(ifaceName)
		if err != nil {
			return fmt.Errorf("failed to retrieve IPv4 address for egress interface: %w", err)
		}

		iface, err := safenetlink.LinkByName(ifaceName)
		if err != nil {
			return fmt.Errorf("failed to retrieve egress interface: %w", err)
		}

		if err = pm.Default(egressIP, uint32(iface.Attrs().Index)); err != nil {
			return fmt.Errorf("failed to configures the default entry in the policy map: %w", err)
		}

		return nil
	}
}
