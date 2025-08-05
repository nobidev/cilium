//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	"context"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/tuple"
	ciliumTypes "github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	servAddr      = "127.0.0.1:30001"
	testNetnsName = "cni-cilium-test-egwha"
	testNetnsDir  = "/var/run/netns/" + testNetnsName
)

// Test_socketsManager tests underying socketManager implementation which iterates
// CNI Pod sockets and terminates them if they match the tuple set.
func TestPrivileged_socketsManager(t *testing.T) {
	testutils.PrivilegedTest(t)
	// use default netns dir not the cilium mounted one.
	tmp := netNSDir
	netNSDir = "/var/run/netns"
	runtime.LockOSThread()
	defer func() {
		netNSDir = tmp
		runtime.UnlockOSThread()
	}()

	// Just in case it wasn't cleaned up previously.
	if _, err := os.Stat(testNetnsDir); err == nil {
		out, err := exec.Command("ip", "netns", "delete", testNetnsName).CombinedOutput()
		if err != nil {
			t.Fatalf("could not cleanup existing ns: %s (%s)", string(out), err)
		}
	}

	curNs, err := netns.Get()
	require.NoError(t, err)
	defer curNs.Close()

	newNs, err := netns.NewNamed(testNetnsName)
	require.NoError(t, err)

	defer newNs.Close()
	defer os.Remove(testNetnsDir)

	// Enter newly create ns (on thread level).
	require.NoError(t, netns.Set(newNs))

	// Bring up loopback.
	lo, err := safenetlink.LinkByName("lo")
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(lo))

	lis, err := net.Listen("tcp", servAddr)
	require.NoError(t, err)
	serverConnClosed := make(chan struct{})

	go func() {
		// Ensure this goroutine runs in the same os-thread,
		// as netns scope is per process/thread.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// Enter newly create ns (on thread level).
		require.NoError(t, netns.Set(newNs))

		conn, err := lis.Accept()
		for {
			require.NoError(t, err)
			buf := make([]byte, 4)
			_, err := conn.Read(buf)
			if err != nil {
				close(serverConnClosed)
				return
			}
			t.Log(string(buf))
		}
	}()

	clientConn, err := net.Dial("tcp", servAddr)
	require.NoError(t, err)
	defer clientConn.Close()
	clientConnClosed := make(chan struct{})
	go func() {
		// Ensure this goroutine runs in the same os-thread,
		// as netns scope is per process/thread.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// Enter newly create ns (on thread level).
		require.NoError(t, netns.Set(newNs))

		for {
			_, err := clientConn.Write([]byte("ping"))
			if err != nil {
				close(clientConnClosed)
				return
			}
			time.Sleep(time.Second)
		}
	}()

	// Leave newly create ns.
	require.NoError(t, netns.Set(curNs))

	// Close sockets is to be called from host net ns
	localConn := clientConn.LocalAddr().String()
	sourcePort, err := strconv.Atoi(strings.Split(localConn, ":")[1])
	require.NoError(t, err)

	h, _ := cell.NewSimpleHealth()
	m := &socketsManager{
		logger: hivetest.Logger(t),
		health: h,
	}

	toClose := sets.New[tuple.TupleKey4]()
	toClose.Insert(tuple.TupleKey4{
		SourceAddr: ciliumTypes.IPv4{127, 0, 0, 1},
		SourcePort: uint16(sourcePort),
		DestAddr:   ciliumTypes.IPv4{127, 0, 0, 1},
		DestPort:   uint16(30001),
		NextHeader: u8proto.TCP,
		Flags:      0x0,
	})
	toClose.Insert(tuple.TupleKey4{
		SourceAddr: ciliumTypes.IPv4{127, 0, 0, 1},
		SourcePort: uint16(sourcePort),
		DestAddr:   ciliumTypes.IPv4{127, 0, 0, 1},
		DestPort:   uint16(30002),
		NextHeader: u8proto.TCP,
		Flags:      0x0,
	})

	stats, err := m.closeSockets(toClose)
	assert.NoError(t, err)
	assert.Equal(t, 1, stats.deleted)
	assert.Equal(t, 0, stats.failed)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	select {
	case <-clientConnClosed:
	case <-ctx.Done():
		t.Fail()
	}
	select {
	case <-serverConnClosed:
	case <-ctx.Done():
		t.Fail()
	}
}
