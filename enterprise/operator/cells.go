//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/features"
	"github.com/cilium/cilium/enterprise/operator/dnsclient"
	"github.com/cilium/cilium/enterprise/operator/dnsresolver"
	enterpriseOperatorK8s "github.com/cilium/cilium/enterprise/operator/k8s"
	"github.com/cilium/cilium/enterprise/operator/pkg/bfd"
	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2"
	"github.com/cilium/cilium/enterprise/operator/pkg/ciliummesh"
	"github.com/cilium/cilium/enterprise/operator/pkg/lb"
	lbmetrics "github.com/cilium/cilium/enterprise/operator/pkg/lb/metrics"
	"github.com/cilium/cilium/enterprise/operator/pkg/multinetwork"
	"github.com/cilium/cilium/enterprise/operator/pkg/networkpolicy"
	"github.com/cilium/cilium/enterprise/operator/pkg/srv6/locatorpool"
	"github.com/cilium/cilium/enterprise/pkg/clustermesh/clustercfg"
	"github.com/cilium/cilium/enterprise/pkg/clustermesh/phantom"
	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha"
	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha/healthcheck"
	"github.com/cilium/cilium/operator/cmd"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

var (
	EnterpriseOperator = cell.Module(
		"enterprise-operator",
		"Cilium Operator Enterprise",

		cmd.Operator,

		// enterprise-only cells here

		cell.Decorate(
			func(lc *cmd.LeaderLifecycle) cell.Lifecycle {
				return lc
			},

			// enterprise-only cells to be started after leader election here
			enterpriseOperatorK8s.ResourcesCell,

			cell.Provide(promise.New[*option.DaemonConfig]),

			cell.Invoke(registerConfigResolution),

			features.OperatorCell,

			locatorpool.Cell,

			dnsclient.Cell,
			dnsresolver.Cell,

			egressgatewayha.OperatorCell,
			egressgatewayha.PolicyCell,
			healthcheck.Cell,
			ciliummesh.Cell,
			cell.Invoke(func(*egressgatewayha.OperatorManager) {}),

			multinetwork.Cell,
			bgpv2.Cell,
			bfd.Cell,

			lb.Cell,
			lbmetrics.Cell,

			networkpolicy.Cell,
			networkpolicy.SecretSyncCell,

			clustercfg.Cell,
			phantom.Cell,
		),
	)
)

// registerConfigResolution sets up a lifecycle hook that ensures configuration
// resolution happens after the legacy operator initialization is complete.
func registerConfigResolution(lc cell.Lifecycle, cfgResolver promise.Resolver[*option.DaemonConfig]) {
	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			// This hook runs after all previous cells in the leader lifecycle have started,
			// including legacyCell. By this point, option.Config should be stable.

			// 'option.Config' is assumed to be stable at this point, except for
			// 'option.Config.Opts' that are explicitly deemed to be runtime-changeable
			cfgResolver.Resolve(option.Config)
			return nil
		},
		OnStop: func(ctx cell.HookContext) error {
			return nil
		},
	})
}
