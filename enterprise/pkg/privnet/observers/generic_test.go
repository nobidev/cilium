//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package observers_test

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/stream"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/observers"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

func TestObserver(t *testing.T) {
	const timeout = 3 * time.Second

	var (
		obs = observers.NewGeneric[string, resource.EventKind]()

		obj1 = "foo"
		obj2 = "bar"
		obj3 = "baz"

		ctx, cancel = context.WithCancel(t.Context())
	)

	// Push a few events before starting the observer.
	obs.Queue(resource.Upsert, obj1)
	obs.Queue(resource.Sync, "")
	obs.Queue(resource.Upsert, obj2)
	obs.Queue(resource.Delete, obj2)

	out := stream.ToChannel(ctx, obs)
	select {
	case got := <-out:
		require.Equal(t, observers.Events[string, resource.EventKind]{
			{Object: obj1, EventKind: resource.Upsert},
			{EventKind: resource.Sync},
			{Object: obj2, EventKind: resource.Upsert},
			{Object: obj2, EventKind: resource.Delete},
		}, got)
	case <-time.After(timeout):
		require.FailNow(t, "No events observed")
	}

	// Push some more updates
	obs.Queue(resource.Upsert, obj1)
	obs.Queue(resource.Upsert, obj2)
	obs.Queue(resource.Delete, obj1)

	var (
		got  observers.Events[string, resource.EventKind]
		tout = time.After(timeout)
	)

outer:
	// Strictly speaking, there's no absolute guarantee that all events are merged
	// into the same buffer. Hence, let's make sure we don't fail in case they are not.
	for {
		select {
		case g := <-out:
			got = append(got, g...)
			if len(got) == 3 {
				require.Equal(t, observers.Events[string, resource.EventKind]{
					{Object: obj1, EventKind: resource.Upsert},
					{Object: obj2, EventKind: resource.Upsert},
					{Object: obj1, EventKind: resource.Delete},
				}, got)
				break outer
			}

		case <-tout:
			require.FailNow(t, "No events observed")
		}
	}

	require.Panics(t, func() { stream.ToChannel(ctx, obs) }, "Observing twice is forbidden")

	cancel()

	select {
	case <-out:
	case <-time.After(timeout):
		require.FailNow(t, "Something went wrong while stopping the observer")
	}

	// Events received after stopping the observer should not hang.
	obs.Queue(resource.Upsert, obj1)
	obs.Queue(resource.Delete, obj3)
	obs.Queue(resource.Sync, obj1)
}
