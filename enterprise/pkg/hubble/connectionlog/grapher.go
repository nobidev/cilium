// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package connectionlog

import (
	"context"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

// connLogger is the glue between connLogDB and Hubble hook system. It
// currently doesn't do much, but support for Hubble flow related features
// (e.g. flow filtering) could be implemented here without adding more logic to
// connLogDB.
type connLogger struct {
	db *connLogDB
}

func newConnLogger(db *connLogDB) *connLogger {
	return &connLogger{db}
}

// OnDecodedFlow implements OnDecodedFlow for connLogger.
func (g *connLogger) OnDecodedFlow(_ context.Context, flow *flowpb.Flow) (bool, error) {
	g.db.add(flow)
	return false, nil
}
