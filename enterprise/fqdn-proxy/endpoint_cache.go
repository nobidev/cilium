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

// AgentDataCache is a cache which stores data retrieved from agent by
// DNS proxy so that proxy can function when agent is unavailable
type AgentDataCache struct {
	endpointByIP map[netip.Addr]*endpoint.Endpoint
	identityByIP map[netip.Addr]ipcache.Identity
	ipBySecID    map[identity.NumericIdentity][]string

	lock lock.RWMutex
}

func NewCache() AgentDataCache {
	return AgentDataCache{
		endpointByIP: make(map[netip.Addr]*endpoint.Endpoint),
		identityByIP: make(map[netip.Addr]ipcache.Identity),
		ipBySecID:    make(map[identity.NumericIdentity][]string),
	}
}
