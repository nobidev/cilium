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
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/datapath/sockets"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ciliumnetns "github.com/cilium/cilium/pkg/netns"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ce-datapath-sockets")

func IterateAs(ns netns.NsHandle, proto netlink.Proto, family uint8, stateFilter uint32, fn func(*netlink.Socket, error) error) error {
	return iterate(&ns, proto, family, stateFilter, func(s *sockets.Socket, err error) error {
		return fn((*netlink.Socket)(s), err)
	})
}

func Iterate(proto netlink.Proto, family uint8, stateFilter uint32, fn func(*netlink.Socket, error) error) error {
	return iterate(nil, proto, family, stateFilter, func(s *sockets.Socket, err error) error {
		return fn((*netlink.Socket)(s), err)
	})
}

func iterate(ns *netns.NsHandle, proto netlink.Proto, family uint8, stateFilter uint32, fn func(*sockets.Socket, error) error) error {
	switch proto {
	case unix.IPPROTO_UDP, unix.IPPROTO_TCP:
	default:
		return fmt.Errorf("unsupported protocol for iterating sockets: %d", proto)
	}
	return iterateNetlinkSockets(ns, proto, family, stateFilter, fn)
}

// DestroySocketAs sends a socket destroy message as the provided network namespce
// via netlink and waits for a ack response.
func DestroySocketAs(ns netns.NsHandle, sock netlink.Socket, proto netlink.Proto, stateFilter uint32) error {
	return destroySocket(&ns, sock.ID, sock.Family, uint8(proto), stateFilter, true)
}

// DestroySocket sends a socket destroy message via netlink and waits for a ack response.
func DestroySocket(sock netlink.Socket, proto netlink.Proto, stateFilter uint32) error {
	return destroySocket(nil, sock.ID, sock.Family, uint8(proto), stateFilter, true)
}

func StateMask(ms ...int) uint32 {
	return stateMask(ms...)
}

func stateMask(ms ...int) uint32 {
	var out uint32
	for _, m := range ms {
		out |= 1 << m
	}
	return out
}

func destroySocket(ns *netns.NsHandle, sockId netlink.SocketID, family uint8, protocol uint8, stateFilter uint32, waitForAck bool) error {
	s, err := openSubscribeHandle(ns)
	if err != nil {
		return err
	}
	defer s.Close()

	params := unix.NLM_F_REQUEST
	if waitForAck {
		params |= unix.NLM_F_ACK
	}
	req := nl.NewNetlinkRequest(sockets.SOCK_DESTROY, params)
	req.AddData(&sockets.SocketRequest{
		Family:   family,
		Protocol: protocol,
		States:   stateFilter,
		ID:       sockId,
	})
	err = s.Send(req)
	if err != nil {
		return fmt.Errorf("error in destroying socket: %w", err)
	}

	if !waitForAck {
		return nil
	}
	msg, _, err := s.Receive()
	if err != nil {
		return fmt.Errorf("failed to recv destroy resp: %w", err)
	}
	for _, m := range msg {
		switch m.Header.Type {
		case unix.NLMSG_ERROR:
			error := int32(nl.NativeEndian().Uint32(m.Data[0:4]))
			errno := syscall.Errno(-error)
			if errno != 0 {
				return fmt.Errorf("got error response to socket destroy: %w", errno)
			}
			return nil
		default:
			log.WithField("nlMsgType", m.Header.Type).
				Info("netlink socket delete received was followed by an unexpected response header type.")
		}
	}

	return err
}

// openSubscribeHandle opens a netlink socket sub. If the netlink handle
// pointer is not nil then it will subscribe to a network-namespaced handle
// otherwise the host handle is returned.
func openSubscribeHandle(ns *netns.NsHandle) (*nl.NetlinkSocket, error) {
	var s *nl.NetlinkSocket
	var err error
	if ns != nil {
		cur, err := ciliumnetns.Current()
		if err != nil {
			return nil, fmt.Errorf("failed to get current network namespace for namespaced socket diag call: %w", err)
		}
		s, err = nl.SubscribeAt(*ns, netns.NsHandle(cur.FD()), unix.NETLINK_INET_DIAG)
		if err != nil {
			return nil, fmt.Errorf("failed to subcribed to namespaced netlink socket: %w", err)
		}
	} else {
		s, err = nl.Subscribe(unix.NETLINK_INET_DIAG)
		if err != nil {
			return nil, err
		}
	}
	return s, err
}

func iterateNetlinkSockets(ns *netns.NsHandle, proto netlink.Proto, family uint8, stateFilter uint32, fn func(*sockets.Socket, error) error) error {
	s, err := openSubscribeHandle(ns)
	if err != nil {
		return err
	}
	defer s.Close()

	req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, unix.NLM_F_DUMP)
	req.AddData(&sockets.SocketRequest{
		Family:   family,
		Protocol: uint8(proto),
		States:   stateFilter,
	})
	s.Send(req)

	for {
		msgs, from, err := s.Receive()
		if err != nil {
			if err := fn(nil, err); err != nil {
				return err
			}
			continue
		}
		if from.Pid != nl.PidKernel {
			if err := fn(nil, fmt.Errorf("Wrong sender portID=%d, expected=%d", from.Pid, nl.PidKernel)); err != nil {
				return err
			}
			continue
		}
		if len(msgs) == 0 {
			if err := fn(nil, errors.New("no message nor error from netlink")); err != nil {
				return err
			}
			continue
		}

		for _, m := range msgs {
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				return nil
			case unix.NLMSG_ERROR:
				error := int32(nl.NativeEndian().Uint32(m.Data[0:4]))
				fn(nil, syscall.Errno(-error))
				continue
			}
			sockInfo := &sockets.Socket{}
			err := sockInfo.Deserialize(m.Data)
			if err := fn(sockInfo, err); err != nil {
				return err
			}
		}
	}
}

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
	if err := Iterate(unix.IPPROTO_UDP, unix.AF_INET, 0xff, func(s *netlink.Socket, err error) error {
		lo := net.IP{127, 0, 0, 1}
		if s.ID.SourcePort == uint16(port) && s.ID.Source.Equal(lo) {
			destroyErr := DestroySocket(*s, unix.IPPROTO_UDP, 0xff)
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
