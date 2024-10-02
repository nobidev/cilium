//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package policy

import (
	"context"

	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/identity/cache"
)

type IdentityChangeBatch = []cache.IdentityChange

func bufferIdentityUpdates(src stream.Observable[cache.IdentityChange]) stream.Observable[IdentityChangeBatch] {
	return stream.FuncObservable[IdentityChangeBatch](func(ctx context.Context, next func(IdentityChangeBatch), complete func(error)) {
		var (
			syncReceived bool
			initialBatch IdentityChangeBatch
		)
		src.Observe(ctx,
			func(change cache.IdentityChange) {
				if !syncReceived {
					// Buffer all changes before the identity sync
					initialBatch = append(initialBatch, change)
					if change.Kind == cache.IdentityChangeSync {
						syncReceived = true
						next(initialBatch) // emit batch
						initialBatch = nil
					}
				} else {
					// Otherwise emit change immediately
					next(IdentityChangeBatch{change})
				}
			},
			complete,
		)
	})
}
