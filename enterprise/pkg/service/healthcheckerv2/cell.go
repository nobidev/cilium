// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package healthcheckerv2

import (
	"github.com/cilium/hive/cell"
)

// Cell implements health checking for load-balancing backends.
//
// The implementation is divided into two parts:
//  1. [controller] which interacts with the load-balancing control-plane
//     and instructs what backends to health check via Table[healthCheck],
//  2. [checker] which probes the backends defined by Table[healthCheck]
//     and updates back.
var Cell = cell.Module(
	"service-health-checker-v2",
	"Service health checking",

	cell.ProvidePrivate(
		newHealthCheckTable,
	),
	cell.Invoke(
		registerController,
		registerChecker,
	),
)
