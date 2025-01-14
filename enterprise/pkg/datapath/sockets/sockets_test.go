// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package sockets

import (
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	servAddr = "127.0.0.1:0"
)

func TestIterateDestroy(t *testing.T) {
	testutils.PrivilegedTest(t)
	setupAndRunTest := func(proto netlink.Proto, testFn func(t *testing.T, clientConn net.Conn, lisAddr string)) {
		u8p, err := u8proto.FromNumber(uint8(proto))
		assert.NoError(t, err)

		var lis net.Listener
		serverConnClosed := make(chan struct{})
		if proto == unix.IPPROTO_TCP {
			lis, err = net.Listen(strings.ToLower(u8p.String()), servAddr)
			require.NoError(t, err)
			go func() {
				conn, err := lis.Accept()
				for {
					require.NoError(t, err)
					buf := make([]byte, 1)
					_, err := conn.Read(buf)
					if errors.Is(err, io.EOF) {
						close(serverConnClosed)
						return
					}
				}
			}()
		} else {
			// Don't need a listener socket for UDP, so we just close.
			close(serverConnClosed)
		}

		lisAddr := servAddr
		if lis != nil {
			lisAddr = lis.Addr().String()
		}

		clientConn, err := net.Dial(strings.ToLower(u8p.String()), lisAddr)
		require.NoError(t, err)
		defer clientConn.Close()
		clientConnClosed := make(chan struct{})
		go func() {
			for {
				_, err := clientConn.Write([]byte("ping"))
				if err != nil {
					close(clientConnClosed)
					return
				}
				time.Sleep(time.Second)
			}
		}()

		testFn(t, clientConn, lisAddr)
		<-clientConnClosed
		<-serverConnClosed
	}
	setupAndRunTest(unix.IPPROTO_TCP, func(t *testing.T, clientConn net.Conn, lisAddr string) {
		assert.NoError(t, Iterate(unix.IPPROTO_TCP, unix.AF_INET, 0xff, func(s *netlink.Socket, err error) error {
			if s == nil {
				return nil
			}
			cc := clientConn.LocalAddr().String()
			sc := s.ID.Destination.String() + ":" + strconv.Itoa(int(s.ID.DestinationPort))
			src := s.ID.Source.String() + ":" + strconv.Itoa(int(s.ID.SourcePort))
			if src == cc && sc == lisAddr {
				assert.NoError(t, DestroySocket(*s, unix.IPPROTO_TCP, 0xff))
			}
			return nil
		}))
	})
	setupAndRunTest(unix.IPPROTO_UDP, func(t *testing.T, clientConn net.Conn, lisAddr string) {
		assert.NoError(t, Iterate(unix.IPPROTO_UDP, unix.AF_INET, 0xff, func(s *netlink.Socket, err error) error {
			if s == nil {
				return nil
			}
			cc := clientConn.LocalAddr().String()
			src := s.ID.Source.String() + ":" + strconv.Itoa(int(s.ID.SourcePort))
			if src == cc {
				assert.NoError(t, DestroySocket(*s, unix.IPPROTO_UDP, 0xff))
			}
			return nil
		}))
	})
}

func TestProbetInetDiagDestroyEnabled(t *testing.T) {
	testutils.PrivilegedTest(t)
	assert.NoError(t, InetDiagDestroyEnabled())
}
