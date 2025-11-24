//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
)

type lockedMap[K comparable, V any] struct {
	mu lock.RWMutex
	m  map[K]V
}

func newLockedMap[K comparable, V any]() *lockedMap[K, V] {
	return &lockedMap[K, V]{
		m: make(map[K]V),
	}
}

func (m *lockedMap[K, V]) Load(k K) (V, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	v, ok := m.m[k]
	return v, ok
}

func (m *lockedMap[K, V]) Store(k K, v V) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.m[k] = v
}

func (m *lockedMap[K, V]) ForEach(handle func(K, V)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for k, v := range m.m {
		handle(k, v)
	}
}

// agentDataCache is a cache which stores data retrieved from agent by
// DNS proxy so that proxy can function when agent is unavailable
type agentDataCache struct {
	endpointByIP *lockedMap[netip.Addr, *endpoint.Endpoint]
	identityByIP *lockedMap[netip.Addr, ipcache.Identity]
	ipBySecID    *lockedMap[identity.NumericIdentity, []string]
}

func newAgentDataCache() *agentDataCache {
	return &agentDataCache{
		endpointByIP: newLockedMap[netip.Addr, *endpoint.Endpoint](),
		identityByIP: newLockedMap[netip.Addr, ipcache.Identity](),
		ipBySecID:    newLockedMap[identity.NumericIdentity, []string](),
	}
}

func (c *agentDataCache) GetEndpointByIP(ip netip.Addr) (*endpoint.Endpoint, bool) {
	return c.endpointByIP.Load(ip)
}

func (c *agentDataCache) UpsertEndpoint(ip netip.Addr, endpoint *endpoint.Endpoint) {
	c.endpointByIP.Store(ip, endpoint)
}

func (c *agentDataCache) GetIdentityByIP(ip netip.Addr) (ipcache.Identity, bool) {
	return c.identityByIP.Load(ip)
}

func (c *agentDataCache) UpsertIdentity(ip netip.Addr, identity ipcache.Identity) {
	c.identityByIP.Store(ip, identity)
}

func (c *agentDataCache) GetIPsBySecID(nid identity.NumericIdentity) ([]string, bool) {
	return c.ipBySecID.Load(nid)
}

func (c *agentDataCache) UpsertIPs(nid identity.NumericIdentity, ips []string) {
	c.ipBySecID.Store(nid, ips)
}
