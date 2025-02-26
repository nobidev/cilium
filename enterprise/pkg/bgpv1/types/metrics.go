// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package types

const (
	// MetricsSubsystem is the name of the metrics subsystem for enterprise BGP Control Plane.
	MetricsSubsystem = "enterprise_bgp_control_plane"

	// MetricReconcileErrorCount is the name of the metric with the number of errors during reconciliation.
	MetricReconcileErrorCount = "reconcile_error_count"
	// MetricReconcileRunDuration is the name of the metric with the duration of the BGP reconciliation run.
	MetricReconcileRunDuration = "reconcile_run_duration_seconds"

	// LabelResourceKind is the metric label for k8s resource kind.
	LabelResourceKind = "resource_kind"
)
