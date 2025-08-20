//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package kvstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/stream"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/kvstore"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

func TestObserver(t *testing.T) {
	const timeout = 3 * time.Second

	var (
		obs = kvstore.NewEndpointObserver()

		ep1 = kvstore.Endpoint{Name: "foo"}
		ep2 = kvstore.Endpoint{Name: "bar"}
		ep3 = kvstore.Endpoint{Name: "baz"}

		VE = func(ep kvstore.Endpoint) *kvstore.ValidatingEndpoint {
			return &kvstore.ValidatingEndpoint{Endpoint: ep}
		}

		ctx, cancel = context.WithCancel(t.Context())
	)

	// Push a few events before starting the observer.
	obs.OnUpdate(VE(ep1))
	obs.OnSync()
	obs.OnUpdate(VE(ep2))
	obs.OnDelete(VE(ep2))

	out := stream.ToChannel(ctx, obs)
	select {
	case got := <-out:
		require.Equal(t, kvstore.EndpointEvents{
			{Endpoint: &ep1, EventKind: resource.Upsert},
			{EventKind: resource.Sync},
			{Endpoint: &ep2, EventKind: resource.Upsert},
			{Endpoint: &ep2, EventKind: resource.Delete},
		}, got)
	case <-time.After(timeout):
		require.FailNow(t, "No events observed")
	}

	// Push some more updates
	obs.OnUpdate(VE(ep1))
	obs.OnUpdate(VE(ep2))
	obs.OnDelete(VE(ep1))

	var (
		got  kvstore.EndpointEvents
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
				require.Equal(t, kvstore.EndpointEvents{
					{Endpoint: &ep1, EventKind: resource.Upsert},
					{Endpoint: &ep2, EventKind: resource.Upsert},
					{Endpoint: &ep1, EventKind: resource.Delete},
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
	obs.OnUpdate(VE(ep1))
	obs.OnDelete(VE(ep3))
	obs.OnSync()
}
