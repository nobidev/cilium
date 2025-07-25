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
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ipcache"
)

type bpfIPCache interface {
	lookup(netip.Addr) (identity.NumericIdentity, error)
}

type bpfIPC struct {
	logger *slog.Logger
}

func newBPFIPCache(logger *slog.Logger) bpfIPCache {
	return &bpfIPC{
		logger: logger,
	}
}

// looks up the identity for a the given IP address from the BPF ipcache map.
func (b *bpfIPC) lookup(addr netip.Addr) (identity.NumericIdentity, error) {
	b.logger.Debug("BPF ipcache lookup", logfields.Address, addr)

	key := ipcache.NewKey(addr.Unmap().AsSlice(), nil, 0)
	// TODO: Add IPCacheMap reload logic, allow to specify name.
	val, err := ipcache.IPCacheMap(nil).Lookup(&key)
	if err != nil {
		return identity.NumericIdentity(0), err
	}

	rei, ok := val.(*ipcache.RemoteEndpointInfo)
	if !ok {
		return identity.NumericIdentity(0), fmt.Errorf("could not cast ipcache bpf map value (%[1]T) %[1]v to %T", rei, &ipcache.RemoteEndpointInfo{})
	}
	return identity.NumericIdentity(rei.SecurityIdentity), nil
}
