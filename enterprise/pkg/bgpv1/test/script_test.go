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
	"strings"
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
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/daemon/cmd"
	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	bfdtypes "github.com/cilium/cilium/enterprise/pkg/bfd/types"
	enterprisebgpv1 "github.com/cilium/cilium/enterprise/pkg/bgpv1"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha"
	"github.com/cilium/cilium/enterprise/pkg/rib"
	"github.com/cilium/cilium/enterprise/pkg/srv6/sidmanager"
	"github.com/cilium/cilium/enterprise/pkg/srv6/srv6manager"
	"github.com/cilium/cilium/pkg/bgpv1"
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager"
	osstest "github.com/cilium/cilium/pkg/bgpv1/test"
	"github.com/cilium/cilium/pkg/bgpv1/test/commands"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	envoyCfg "github.com/cilium/cilium/pkg/envoy/config"
	ciliumhive "github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	k8sfake "github.com/cilium/cilium/pkg/k8s/client/testutils"
	k8sTestutils "github.com/cilium/cilium/pkg/k8s/testutils"
	k8sVersion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbcell "github.com/cilium/cilium/pkg/loadbalancer/cell"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/maps/srv6map"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/svcrouteconfig"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

const (
	testTimeout = 60 * time.Second

	// test resource names
	testNodeName         = "test-node"
	testSecretsNamespace = "kube-system"
	testLink1Name        = "centbgptest1"
	testLink2Name        = "centbgptest2"

	// test arguments
	testPeeringIPsFlag     = "test-peering-ips"
	ipamFlag               = "ipam"
	probeTCPMD5Flag        = "probe-tcp-md5"
	requireIPv6LLAddrsFlag = "require-ipv6-lladdrs"

	// test environment variables
	link1EnvVar   = "LINK1"
	link2EnvVar   = "LINK2"
	llAddr1EnvVar = "LLADDR1"
	llAddr2EnvVar = "LLADDR2"
)

func TestPrivilegedScript(t *testing.T) {
	testutils.PrivilegedTest(t)
	slog.SetLogLoggerLevel(slog.LevelDebug) // used by test GoBGP instances
	k8sVersion.Force(k8sTestutils.DefaultVersion)

	types.SetName(testNodeName)

	// set test environment variables
	envVars := []string{"PATH=" + os.Getenv("PATH")}

	// setup test links
	envVars = setupTestLinks(t, envVars)

	setup := func(t testing.TB, args []string) *script.Engine {
		var (
			err        error
			bgpMgr     agent.BGPRouterManager
			egwMgrMock *egwManagerMock
		)

		// parse the shebang arguments in the script
		flags := pflag.NewFlagSet("test-flags", pflag.ContinueOnError)
		peeringIPs := flags.StringSlice(testPeeringIPsFlag, nil, "List of IPs used for peering in the test")
		useIPAM := flags.String(ipamFlag, ipamOption.IPAMKubernetes, "IPAM used by the test")
		probeTCPMD5 := flags.Bool(probeTCPMD5Flag, false, "Probe if TCP_MD5SIG socket option is available")
		requireIPv6LLAddrs := flags.Bool(requireIPv6LLAddrsFlag, false, "Require IPv6 link local addresses to be present on the test links")
		require.NoError(t, flags.Parse(args), "Error parsing test flags")

		if *probeTCPMD5 {
			available, err := osstest.TCPMD5SigAvailable()
			require.NoError(t, err)
			if !available {
				t.Skip("TCP_MD5SIG socket option is not available")
			}
		}
		if *requireIPv6LLAddrs {
			if !hasIPv6LLAddrs(envVars) {
				t.Skip("Link-local IPv6 addresses not available on test interfaces")
			}
		}

		h := ciliumhive.New(
			k8sfake.FakeClientCell(),
			daemonk8s.ResourcesCell,
			daemonk8s.TablesCell,
			cell.Config(envoyCfg.SecretSyncConfig{}),
			metrics.Cell,
			lbcell.Cell,
			maglev.Cell,
			cell.Provide(source.NewSources),
			cell.Config(loadbalancer.TestConfig{}),
			cell.Provide(
				func(cfg loadbalancer.TestConfig) *loadbalancer.TestConfig { return &cfg }, // newLBMaps expects *TestConfig
			),
			cell.Config(cmtypes.DefaultClusterInfo),
			cell.Config(svcrouteconfig.DefaultConfig),

			// OSS BGP cell
			bgpv1.Cell,

			// Enterprise BGP + SRv6 cells
			enterprisebgpv1.Cell,
			sidmanager.SIDManagerCell,
			srv6manager.Cell,
			srv6map.Cell,
			rib.Cell,
			rib.NopDataPlaneCell,

			// Enterprise BGP dependencies
			cell.Provide(
				tables.NewDeviceTable,
				tables.NewNeighborTable,
				tables.NewRouteTable,
				tables.NewNodeAddressTable,
				bfdtypes.NewBFDPeersTable,

				statedb.RWTable[*tables.Route].ToTable,
				statedb.RWTable[*tables.Device].ToTable,
				statedb.RWTable[*tables.Neighbor].ToTable,
				statedb.RWTable[tables.NodeAddress].ToTable,
				statedb.RWTable[*bfdtypes.BFDPeerStatus].ToTable,
			),
			cell.Provide(func(sig *signaler.BGPCPSignaler) egressgatewayha.EgressIPsProvider {
				egwMgrMock = newEGWManagerMock(sig)
				return egwMgrMock
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
				func() *ipam.IPAM {
					return &ipam.IPAM{}
				},
			),

			// OSS + CEE BGP DaemonConfig
			cell.Provide(func() *option.DaemonConfig {
				// BGP Manager uses the global variable option.Config so we need to set it there as well
				option.Config = &option.DaemonConfig{
					EnableBGPControlPlane:     true,
					BGPSecretsNamespace:       testSecretsNamespace,
					BGPRouterIDAllocationMode: option.BGPRouterIDAllocationModeDefault,
					IPAM:                      *useIPAM,
					EnableIPv4:                true,
					EnableIPv6:                true,
					EnterpriseDaemonConfig: option.EnterpriseDaemonConfig{
						EnableEnterpriseBGPControlPlane: true,
						EnableBFD:                       true,
						EnableIPv4EgressGatewayHA:       true,
					},
				}
				return option.Config
			},
				func() kpr.KPRConfig {
					return kpr.KPRConfig{
						KubeProxyReplacement: true,
					}
				},
			),

			// Enterprise BFD config
			cell.Config(bfdtypes.BFDConfig{
				BFDEnabled: true,
			}),

			node.LocalNodeStoreTestCell,
			cell.Invoke(func() {
				types.SetName(testNodeName)
			}),
			cell.Invoke(func(m agent.BGPRouterManager) {
				bgpMgr = m
			}),

			cell.Provide(
				func() *egwManagerMock {
					return egwMgrMock
				},
				BGPTestScriptCmds,
			),
			cell.Invoke(func(m agent.BGPRouterManager) {
				bgpMgr = m
				m.(*manager.BGPRouterManager).DestroyRouterOnStop(true) // fully destroy GoBGP server on Stop()
			}),
		)
		hive.AddConfigOverride(h, func(cfg *reconcilerv2.Config) {
			cfg.SvcHealthCheckingEnabled = true
			cfg.MaintenanceGracefulShutdownEnabled = true
			cfg.MaintenanceWithdrawTime = 1 * time.Second
		})
		hive.AddConfigOverride(h, func(cfg *config.Config) {
			cfg.Enabled = true
		})

		hiveLog := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
		t.Cleanup(func() {
			assert.NoError(t, h.Stop(hiveLog, context.TODO()))
		})

		// setup test peering IPs
		setupTestPeeringIPs(t, *peeringIPs)

		// set up GoBGP command
		gobgpCmdCtx := commands.NewGoBGPCmdContext()
		t.Cleanup(gobgpCmdCtx.Cleanup)

		cmds, err := h.ScriptCommands(hiveLog)
		require.NoError(t, err, "ScriptCommands")
		maps.Insert(cmds, maps.All(script.DefaultCmds()))
		maps.Insert(cmds, maps.All(commands.GoBGPScriptCmds(gobgpCmdCtx)))
		maps.Insert(cmds, maps.All(CEEGoBGPScriptCmds(gobgpCmdCtx)))
		maps.Insert(cmds, maps.All(commands.BGPScriptCmds(bgpMgr)))

		return &script.Engine{
			Cmds: cmds,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)

	scripttest.Test(t,
		ctx,
		setup,
		envVars,
		"testdata/*.txtar")
}

func setupTestLinks(t *testing.T, envVars []string) []string {
	envVars = append(envVars, []string{
		link1EnvVar + "=" + testLink1Name,
		link2EnvVar + "=" + testLink2Name,
	}...)

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: testLink1Name},
		PeerName:  testLink2Name,
	}
	netlink.LinkDel(veth) // cleanup from potential interrupted test run
	err := netlink.LinkAdd(veth)
	require.NoError(t, err, "error by adding veth %s", testLink1Name)
	t.Cleanup(func() {
		// cleanup after test finishes
		netlink.LinkDel(veth)
	})

	veth1, err := safenetlink.LinkByName(testLink1Name)
	require.NoError(t, err)
	veth2, err := safenetlink.LinkByName(testLink2Name)
	require.NoError(t, err)

	err = netlink.LinkSetUp(veth1)
	require.NoError(t, err)
	err = netlink.LinkSetUp(veth2)
	require.NoError(t, err)

	addrs, err := safenetlink.AddrList(veth1, netlink.FAMILY_V6)
	require.NoError(t, err)
	for _, addr := range addrs {
		if addr.IP.IsLinkLocalUnicast() {
			envVars = append(envVars, llAddr1EnvVar+"="+addr.IP.String())
		}
	}
	addrs, err = safenetlink.AddrList(veth2, netlink.FAMILY_V6)
	require.NoError(t, err)
	for _, addr := range addrs {
		if addr.IP.IsLinkLocalUnicast() {
			envVars = append(envVars, llAddr2EnvVar+"="+addr.IP.String())
		}
	}
	return envVars
}

func setupTestPeeringIPs(t testing.TB, peeringIPs []string) {
	l, err := safenetlink.LinkByName(testLink1Name)
	require.NoError(t, err)
	for _, ip := range peeringIPs {
		ipAddr, err := netip.ParseAddr(ip)
		require.NoError(t, err)
		bits := 32
		if ipAddr.Is6() {
			bits = 128
		}
		prefix := netip.PrefixFrom(ipAddr, bits)
		err = netlink.AddrAdd(l, createNetlinkAddr(prefix))
		if err != nil && os.IsExist(err) {
			t.Fatalf("Peering address %s is probably already used by another test", ip)
		}
		require.NoError(t, err)
	}
}

// createNetlinkAddr creates new netlink.Addr for the provided prefix
func createNetlinkAddr(prefix netip.Prefix) *netlink.Addr {
	pLen := 128
	if prefix.Addr().Is4() {
		pLen = 32
	}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   prefix.Addr().AsSlice(),
			Mask: net.CIDRMask(prefix.Bits(), pLen),
		},
	}
	if prefix.Addr().Is6() {
		addr.Flags = unix.IFA_F_NODAD // disable duplicate address detection so that we can use the address immediately
	}
	return addr
}

// hasIPv6LLAddrs returns true IPv6 link-local addresses were found on both test links
func hasIPv6LLAddrs(envVars []string) bool {
	found := 0
	for _, v := range envVars {
		if strings.HasPrefix(v, llAddr1EnvVar) || strings.HasPrefix(v, llAddr2EnvVar) {
			found++
			if found == 2 {
				return true
			}
		}
	}
	return false
}
