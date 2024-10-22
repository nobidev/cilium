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
	"sync"
	"testing"

	"github.com/cilium/stream"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
)

func Test_identityObserver(t *testing.T) {
	const fooIdentity = 1001
	fooLabels := labels.NewLabelsFromModel([]string{
		k8sLabel("foo", "1"),
	})
	const barIdentity = 2002
	barLabels := labels.NewLabelsFromModel([]string{
		k8sLabel("bar", "2"),
	})
	const bazIdentity = 3003
	bazLabels := labels.NewLabelsFromModel([]string{
		k8sLabel("baz", "3"),
	})
	const quxIdentity = 4004
	quxLabels := labels.NewLabelsFromModel([]string{
		k8sLabel("qux", "4"),
	})

	observer := newIdentityObserver()

	wg := &sync.WaitGroup{}

	// Issue updates before Observe is called
	observer.UpdateIdentities(identity.IdentityMap{
		fooIdentity: fooLabels.LabelArray(),
		barIdentity: barLabels.LabelArray(),
	}, nil, wg)
	observer.UpdateIdentities(identity.IdentityMap{
		bazIdentity: bazLabels.LabelArray(),
	}, nil, wg)

	// Start observing
	ctx, cancel := context.WithCancel(context.Background())
	ch := stream.ToChannel(ctx, observer)

	require.Equal(t, IdentityChangeBatch{Added: identity.IdentityMap{
		fooIdentity: fooLabels.LabelArray(),
		barIdentity: barLabels.LabelArray(),
	}}, <-ch)

	// Issue another update while there are still pending batches
	observer.UpdateIdentities(nil, identity.IdentityMap{
		barIdentity: barLabels.LabelArray(),
	}, wg)

	// Drain channel
	require.Equal(t, IdentityChangeBatch{Added: identity.IdentityMap{
		bazIdentity: bazLabels.LabelArray(),
	}}, <-ch)
	require.Equal(t, IdentityChangeBatch{Deleted: identity.IdentityMap{
		barIdentity: barLabels.LabelArray(),
	}}, <-ch)

	// Issue some more pending updates while consumer is now waiting
	observer.UpdateIdentities(identity.IdentityMap{
		quxIdentity: quxLabels.LabelArray(),
	}, nil, wg)

	// Ensure consumer was woken up
	require.Equal(t, IdentityChangeBatch{Added: identity.IdentityMap{
		quxIdentity: quxLabels.LabelArray(),
	}}, <-ch)

	// Stop observing
	cancel()

	// Channel should be closed
	_, ok := <-ch
	require.False(t, ok)
}
