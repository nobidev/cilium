//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package checker

import "github.com/cilium/hive/cell"

var Cell = cell.Group(
	cell.ProvidePrivate(
		// Provide the connection factory via hive, so that it can be
		// overridden for testing purposes.
		newDefaultConnFactory,

		// Provide the identifiers of the local node via hive, so that it
		// can be overridden for testing purposes.
		newDefaultLocalNode,
	),

	cell.Provide(
		// Provide the health checker implementation.
		New,
	),
)
