// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// This file originates from Ciliums's codebase is governed by an
// Apache 2.0 license (see original header below):
//
// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sockets

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	ciliumSockets "github.com/cilium/cilium/pkg/datapath/sockets"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var probeForDestroy = sync.OnceValue(func() error {
	lis, err := net.ListenUDP("udp", &net.UDPAddr{
		IP: net.IP{127, 0, 0, 1},
	})
	if err != nil {
		return err
	}

	defer lis.Close()
	addrToks := strings.Split(lis.LocalAddr().String(), ":")
	if len(addrToks) != 2 {
		return fmt.Errorf("unexpected listener addr %q, expected format <ip>:<port>", lis.LocalAddr().String())
	}
	port, err := strconv.Atoi(addrToks[1])
	if err != nil {
		return err
	}

	ok := false
	if err := ciliumSockets.Iterate(unix.IPPROTO_UDP, unix.AF_INET, 0xff, func(s *netlink.Socket, err error) error {
		lo := net.IP{127, 0, 0, 1}
		if s.ID.SourcePort == uint16(port) && s.ID.Source.Equal(lo) {
			destroyErr := ciliumSockets.DestroySocket(slog.Default(), *s, unix.IPPROTO_UDP, 0xff)
			if errors.Is(destroyErr, unix.ENOENT) {
				// Note: Returning error stops iteration and passes err through to
				// return value of Iterate.
				return probes.ErrNotSupported
			}
			if destroyErr != nil {
				return destroyErr
			}
			ok = true
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed while iterating sockets: %w", err)
	}
	if !ok {
		return fmt.Errorf("failed to find listener socket for inet diag destroy probe")
	}
	return nil
})

// InetDiagDestroyEnabled sets up a local listener socket on localhost
// and attempts to terminate it to probe for functionality enabled by
// CONFIG_INET_DIAG_DESTROY.
func InetDiagDestroyEnabled() error {
	return probeForDestroy()
}
