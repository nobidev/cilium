// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestWatchResourcesSotWImmediateOnAddForcesVersionWhenCacheUnchanged(t *testing.T) {
	logger := hivetest.Logger(t)
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	cache := NewCache(logger)
	watcher := NewResourceWatcher(logger, typeURL, cache)
	cache.AddResourceVersionObserver(watcher)

	version, updated, _ := cache.TX(typeURL, map[string]proto.Message{
		resources[0].Name: resources[0],
		resources[1].Name: resources[1],
	}, nil)
	require.True(t, updated)
	require.Equal(t, uint64(2), version)

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	out := make(chan *VersionedResources, 1)
	go watcher.WatchResourcesSotW(ctx, typeURL, 2, 2, []string{resources[0].Name, resources[1].Name}, true, out)

	select {
	case <-ctx.Done():
		t.Fatal("timed out waiting for immediate SotW response")
	case resp := <-out:
		require.NotNil(t, resp)
		require.Equal(t, uint64(3), resp.Version)
		require.Len(t, resp.VersionedResources, 2)
	}

	current := cache.GetResources(typeURL, 0, nil)
	require.NotNil(t, current)
	require.Equal(t, uint64(3), current.Version)
}

func TestWatchResourcesSotWImmediateOnAddUsesCurrentVersion(t *testing.T) {
	logger := hivetest.Logger(t)
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	cache := NewCache(logger)
	watcher := NewResourceWatcher(logger, typeURL, cache)
	cache.AddResourceVersionObserver(watcher)

	_, updated, _ := cache.Upsert(typeURL, resources[0].Name, resources[0])
	require.True(t, updated)
	_, updated, _ = cache.Upsert(typeURL, resources[1].Name, resources[1])
	require.True(t, updated)

	current := cache.GetResources(typeURL, 0, nil)
	require.NotNil(t, current)
	require.Equal(t, uint64(3), current.Version)

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	out := make(chan *VersionedResources, 1)
	go watcher.WatchResourcesSotW(ctx, typeURL, 2, 2, []string{resources[0].Name, resources[1].Name}, true, out)

	select {
	case <-ctx.Done():
		t.Fatal("timed out waiting for immediate SotW response")
	case resp := <-out:
		require.NotNil(t, resp)
		require.Equal(t, uint64(3), resp.Version)
		require.Len(t, resp.VersionedResources, 2)
	}

	current = cache.GetResources(typeURL, 0, nil)
	require.NotNil(t, current)
	require.Equal(t, uint64(3), current.Version)
}

func TestWatchResourcesDeltaSubscriptionChangeRespondsImmediately(t *testing.T) {
	logger := hivetest.Logger(t)
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	cache := NewCache(logger)
	watcher := NewResourceWatcher(logger, typeURL, cache)
	cache.AddResourceVersionObserver(watcher)

	_, updated, _ := cache.Upsert(typeURL, resources[0].Name, resources[0])
	require.True(t, updated)

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	out := make(chan *VersionedResources, 1)
	go watcher.WatchResourcesDelta(ctx, typeURL, 2, 2, []string{resources[0].Name}, map[string]struct{}{}, []string{resources[0].Name}, true, out)

	select {
	case <-ctx.Done():
		t.Fatal("timed out waiting for immediate delta response")
	case resp := <-out:
		require.NotNil(t, resp)
		require.Equal(t, uint64(2), resp.Version)
		require.Len(t, resp.VersionedResources, 1)
		require.Equal(t, resources[0].Name, resp.VersionedResources[0].Name)
		require.Equal(t, uint64(2), resp.VersionedResources[0].Version)
	}
}

func TestWatchResourcesDeltaPureAckWaitsForNextVersion(t *testing.T) {
	logger := hivetest.Logger(t)
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	cache := NewCache(logger)
	watcher := NewResourceWatcher(logger, typeURL, cache)
	cache.AddResourceVersionObserver(watcher)

	_, updated, _ := cache.Upsert(typeURL, resources[0].Name, resources[0])
	require.True(t, updated)

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	out := make(chan *VersionedResources, 1)
	go watcher.WatchResourcesDelta(ctx, typeURL, 2, 2, []string{resources[0].Name}, map[string]struct{}{resources[0].Name: {}}, nil, false, out)

	select {
	case resp := <-out:
		t.Fatalf("received unexpected immediate delta response: %+v", resp)
	case <-time.After(100 * time.Millisecond):
	}

	resource0Updated := &envoy_config_route.RouteConfiguration{
		Name:         resources[0].Name,
		VirtualHosts: []*envoy_config_route.VirtualHost{{Name: "vh0"}},
	}
	_, updated, _ = cache.Upsert(typeURL, resource0Updated.Name, resource0Updated)
	require.True(t, updated)

	select {
	case <-ctx.Done():
		t.Fatal("timed out waiting for delta response after cache update")
	case resp := <-out:
		require.NotNil(t, resp)
		require.Equal(t, uint64(3), resp.Version)
		require.Len(t, resp.VersionedResources, 1)
		require.Equal(t, resources[0].Name, resp.VersionedResources[0].Name)
		require.Equal(t, uint64(3), resp.VersionedResources[0].Version)
	}
}
