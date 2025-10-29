//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package server

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

var Cell = cell.Group(
	cell.ProvidePrivate(
		// Provides the connection factory via hive, so that it can be
		// overridden for testing purposes.
		newDefaultListenerFactory,

		// Provides the ReadWrite active networks table.
		tables.NewActiveNetworksTable,

		// Provides the server implementation.
		newServer,
	),

	cell.Provide(
		// Provides the ReadOnly active networks table.
		statedb.RWTable[tables.ActiveNetwork].ToTable,
	),
)
