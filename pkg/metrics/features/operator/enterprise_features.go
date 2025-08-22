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
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
)

func updateEnterpriseOperatorConfigMetricOnStart(jg job.Group, params enterpriseFeaturesParams, m enterpriseFeatureMetrics) error {
	jg.Add(job.OneShot("update-enterprise-operator-config-metric", func(ctx context.Context, health cell.Health) error {
		// We depend on settings modified by the Operator startup.
		// Once the Operator is initialized this promise
		// is resolved and we are guaranteed to have the correct settings.
		health.OK("Waiting for operator config")
		m.update(&params, params.OperatorConfig, params.DaemonConfig)
		return nil
	}))

	return nil
}
