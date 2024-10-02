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
	"testing"

	"github.com/cilium/stream"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity/cache"
)

func Test_bufferIdentityUpdates(t *testing.T) {
	src := stream.FromSlice([]cache.IdentityChange{
		{Kind: cache.IdentityChangeUpsert, ID: 1},
		{Kind: cache.IdentityChangeUpsert, ID: 2},
		{Kind: cache.IdentityChangeUpsert, ID: 3},
		{Kind: cache.IdentityChangeSync},
		{Kind: cache.IdentityChangeDelete, ID: 3},
		{Kind: cache.IdentityChangeUpsert, ID: 4},
		{Kind: cache.IdentityChangeUpsert, ID: 5},
	})

	buffered := bufferIdentityUpdates(src)

	out, err := stream.ToSlice(context.TODO(), buffered)
	require.NoError(t, err)
	require.Equal(t, []IdentityChangeBatch{
		{
			{Kind: cache.IdentityChangeUpsert, ID: 1},
			{Kind: cache.IdentityChangeUpsert, ID: 2},
			{Kind: cache.IdentityChangeUpsert, ID: 3},
			{Kind: cache.IdentityChangeSync},
		},
		{
			{Kind: cache.IdentityChangeDelete, ID: 3},
		},
		{
			{Kind: cache.IdentityChangeUpsert, ID: 4},
		},
		{
			{Kind: cache.IdentityChangeUpsert, ID: 5},
		},
	}, out)
}
