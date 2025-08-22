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
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
)

// EnterpriseMetrics represents a collection of enterprise metrics related to a specific feature.
// Each field is named according to the specific feature that it tracks.
type EnterpriseMetrics struct {
	ACLBSRv6 metric.Gauge
}

const (
	enterprise = "enterprise_"
)

// NewEnterpriseMetrics returns all enterprise feature metrics. If 'withDefaults' is set, then
// all metrics will have defined all of their possible values.
func NewEnterpriseMetrics(withDefaults bool) EnterpriseMetrics {
	return EnterpriseMetrics{
		ACLBSRv6: metric.NewGauge(metric.GaugeOpts{
			Help:      "Cilium SRv6 enabled on the agent",
			Namespace: metrics.Namespace,
			Subsystem: enterprise + subsystemACLB,
			Name:      "srv6_enabled",
		}),
	}
}

type enterpriseFeatureMetrics interface {
	update(params enabledEnterpriseFeatures, config *option.DaemonConfig)
}

func (m EnterpriseMetrics) update(params enabledEnterpriseFeatures, config *option.DaemonConfig) {
	if config.EnableSRv6 {
		m.ACLBSRv6.Set(1)
	}
}
