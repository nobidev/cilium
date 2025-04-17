// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package test

import (
	"context"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/daemon/cmd"
	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	bfdtypes "github.com/cilium/cilium/enterprise/pkg/bfd/types"
	enterprisebgpv1 "github.com/cilium/cilium/enterprise/pkg/bgpv1"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha"
	"github.com/cilium/cilium/enterprise/pkg/srv6/sidmanager"
	"github.com/cilium/cilium/enterprise/pkg/srv6/srv6manager"
	"github.com/cilium/cilium/pkg/bgpv1"
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	osstest "github.com/cilium/cilium/pkg/bgpv1/test"
	"github.com/cilium/cilium/pkg/bgpv1/test/commands"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"
	ciliumhive "github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity/cache"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/maps/srv6map"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

const (
	testTimeout = 60 * time.Second

	// test resource names
	testNodeName         = "test-node"
	testSecretsNamespace = "kube-system"
	testLinkName         = "cilium-bgp-test"

	// test arguments
	testPeeringIPsFlag = "test-peering-ips"
	ipamFlag           = "ipam"
	probeTCPMD5Flag    = "probe-tcp-md5"
)

func TestScript(t *testing.T) {
	testutils.PrivilegedTest(t)
	slog.SetLogLoggerLevel(slog.LevelDebug) // used by test GoBGP instances

	// setup test link
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: testLinkName},
	}
	netlink.LinkDel(dummy) // cleanup from potential previous test run
	err := netlink.LinkAdd(dummy)
	require.NoError(t, err, "error by adding test link %s", testLinkName)
	t.Cleanup(func() {
		netlink.LinkDel(dummy)
	})

	setup := func(t testing.TB, args []string) *script.Engine {
		var (
			err           error
			bgpMgr        agent.BGPRouterManager
			fakeClientSet *client.FakeClientset
			egwMgrMock    *egwManagerMock
			svcHcMgrMock  *serviceHealthCheckManagerMock
		)

		// parse the shebang arguments in the script
		flags := pflag.NewFlagSet("test-flags", pflag.ContinueOnError)
		peeringIPs := flags.StringSlice(testPeeringIPsFlag, nil, "List of IPs used for peering in the test")
		ipam := flags.String(ipamFlag, ipamOption.IPAMKubernetes, "IPAM used by the test")
		probeTCPMD5 := flags.Bool(probeTCPMD5Flag, false, "Probe if TCP_MD5SIG socket option is available")
		require.NoError(t, flags.Parse(args), "Error parsing test flags")

		if *probeTCPMD5 {
			available, err := osstest.TCPMD5SigAvailable()
			require.NoError(t, err)
			if !available {
				t.Skip("TCP_MD5SIG socket option is not available")
			}
		}

		h := ciliumhive.New(
			client.FakeClientCell,
			daemonk8s.ResourcesCell,
			metrics.Cell,

			// OSS BGP cell
			bgpv1.Cell,

			// Enterprise BGP + SRv6 cells
			enterprisebgpv1.Cell,
			sidmanager.SIDManagerCell,
			srv6manager.Cell,
			srv6map.Cell,

			// Enterprise BGP dependencies
			cell.Provide(
				tables.NewDeviceTable,
				tables.NewNeighborTable,
				bfdtypes.NewBFDPeersTable,

				statedb.RWTable[*tables.Device].ToTable,
				statedb.RWTable[*tables.Neighbor].ToTable,
				statedb.RWTable[*bfdtypes.BFDPeerStatus].ToTable,
			),
			cell.Invoke(statedb.RegisterTable[*tables.Device]),
			cell.Invoke(statedb.RegisterTable[*tables.Neighbor]),
			cell.Invoke(statedb.RegisterTable[*bfdtypes.BFDPeerStatus]),
			cell.Provide(func(sig *signaler.BGPCPSignaler) egressgatewayha.EgressIPsProvider {
				egwMgrMock = newEGWManagerMock(sig)
				return egwMgrMock
			}),
			cell.Provide(func() service.ServiceHealthCheckManager {
				svcHcMgrMock = newServiceHealthCheckManagerMock()
				return svcHcMgrMock
			}),

			// SRv6 dependencies
			cell.Provide(
				func() cache.IdentityAllocator {
					return testidentity.NewMockIdentityAllocator(nil)
				},
				func() promise.Promise[*cmd.Daemon] {
					daemonResolver, daemonPromise := promise.New[*cmd.Daemon]()
					daemonResolver.Resolve(&cmd.Daemon{})
					return daemonPromise
				},
			),

			// OSS + CEE BGP DaemonConfig
			cell.Provide(func() *option.DaemonConfig {
				// BGP Manager uses the global variable option.Config so we need to set it there as well
				option.Config = &option.DaemonConfig{
					EnableBGPControlPlane:     true,
					BGPSecretsNamespace:       testSecretsNamespace,
					BGPRouterIDAllocationMode: defaults.BGPRouterIDAllocationMode,
					IPAM:                      *ipam,
					EnterpriseDaemonConfig: option.EnterpriseDaemonConfig{
						EnableEnterpriseBGPControlPlane: true,
						EnableBFD:                       true,
						EnableIPv4EgressGatewayHA:       true,
					},
				}
				return option.Config
			}),

			// Enterprise BFD config
			cell.Config(bfdtypes.BFDConfig{
				BFDEnabled: true,
			}),

			node.LocalNodeStoreCell,
			cell.Invoke(func() {
				types.SetName(testNodeName)
			}),
			cell.Invoke(func(m agent.BGPRouterManager) {
				bgpMgr = m
			}),
			cell.Invoke(func(cs *client.FakeClientset) {
				fakeClientSet = cs
			}),
		)
		hive.AddConfigOverride(h, func(cfg *reconcilerv2.Config) {
			cfg.SvcHealthCheckingEnabled = true
		})
		hive.AddConfigOverride(h, func(cfg *config.Config) {
			cfg.Enabled = true
		})

		hiveLog := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
		t.Cleanup(func() {
			assert.NoError(t, h.Stop(hiveLog, context.TODO()))
		})

		// setup test peering IPs
		l, err := netlink.LinkByName(testLinkName)
		require.NoError(t, err)
		for _, ip := range *peeringIPs {
			ipAddr, err := netip.ParseAddr(ip)
			require.NoError(t, err)
			bits := 32
			if ipAddr.Is6() {
				bits = 128
			}
			prefix := netip.PrefixFrom(ipAddr, bits)
			err = netlink.AddrAdd(l, toNetlinkAddr(prefix))
			if err != nil && os.IsExist(err) {
				t.Fatalf("Peering address %s is probably already used by another test", ip)
			}
			require.NoError(t, err)
		}

		// set up GoBGP command
		gobgpCmdCtx := commands.NewGoBGPCmdContext()
		t.Cleanup(gobgpCmdCtx.Cleanup)

		cmds, err := h.ScriptCommands(hiveLog)
		require.NoError(t, err, "ScriptCommands")
		maps.Insert(cmds, maps.All(script.DefaultCmds()))
		maps.Insert(cmds, maps.All(commands.GoBGPScriptCmds(gobgpCmdCtx)))
		maps.Insert(cmds, maps.All(commands.BGPScriptCmds(bgpMgr)))
		maps.Insert(cmds, maps.All(BGPTestScriptCmds(fakeClientSet, egwMgrMock, svcHcMgrMock)))

		return &script.Engine{
			Cmds: cmds,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)

	scripttest.Test(t,
		ctx,
		setup,
		[]string{"PATH=" + os.Getenv("PATH")},
		"testdata/*.txtar")
}

// toNetlinkAddr converts netip.Prefix to *netlink.Addr
func toNetlinkAddr(prefix netip.Prefix) *netlink.Addr {
	pLen := 128
	if prefix.Addr().Is4() {
		pLen = 32
	}
	return &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   prefix.Addr().AsSlice(),
			Mask: net.CIDRMask(prefix.Bits(), pLen),
		},
	}
}
