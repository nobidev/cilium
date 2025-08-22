//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package features

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	bgpconfig "github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

// EnterpriseCell will retrieve information from all other cells /
// configuration to describe, in form of prometheus metrics, which
// enterprise features are enabled on the agent.
var EnterpriseCell = cell.Module(
	"enabled-enterprise-features",
	"Exports prometheus metrics showing which ent feat are enabled in cilium-agent",

	cell.Invoke(updateEnterpriseAgentConfigMetricOnStart),
	cell.Provide(
		func(m EnterpriseMetrics) enterpriseFeatureMetrics {
			return m
		},
	),
	metrics.Metric(func() EnterpriseMetrics {
		if withDefaults != "" {
			return NewEnterpriseMetrics(true)
		}
		return NewEnterpriseMetrics(false)
	}),
)

type enterpriseFeaturesParams struct {
	cell.In

	Log           *slog.Logger
	JobGroup      job.Group
	Health        cell.Health
	Lifecycle     cell.Lifecycle
	ConfigPromise promise.Promise[*option.DaemonConfig]
	Metrics       enterpriseFeatureMetrics

	BGP bgpconfig.Config
}

func (fp *enterpriseFeaturesParams) IsEnterpriseBGPEnabled() bool {
	return fp.BGP.IsEnabled()
}

type enabledEnterpriseFeatures interface {
	IsEnterpriseBGPEnabled() bool
}
