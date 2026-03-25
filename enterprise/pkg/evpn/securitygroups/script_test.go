// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law. Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package securitygroups

import (
	"context"
	"fmt"
	"maps"
	"net"
	"strconv"
	"testing"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/workqueue"

	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	"github.com/cilium/cilium/enterprise/pkg/evpn/securitygroups/tables"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	k8sTestutils "github.com/cilium/cilium/pkg/k8s/testutils"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/promise"
)

func TestScript(t *testing.T) {
	version.Force(k8sTestutils.DefaultVersion)
	nodeTypes.SetName("testnode")

	scripttest.Test(t, t.Context(), func(t testing.TB, args []string) *script.Engine {
		// parse the shebang arguments in the script
		flags := pflag.NewFlagSet("", pflag.ContinueOnError)
		nodeIP := flags.String("test-node-ip", "", "Node IP used by the test")
		defaultGroupIP := flags.Uint16(evpnConfig.FlagDefaultSecurityGroupID, 0, "Default Security Group ID used by the test")
		require.NoError(t, flags.Parse(args), "Error parsing test flags")

		log := hivetest.Logger(t)
		h := hive.New(
			k8sClient.FakeClientCell(),
			node.LocalNodeStoreTestCell,
			evpnConfig.Cell,

			cell.Provide(
				tables.NewSecurityGroupsTable,
				tables.NewEndpointSecurityGroupTable,
				statedb.RWTable[tables.SecurityGroup].ToTable,
				statedb.RWTable[tables.EndpointSecurityGroup].ToTable,

				newSecurityGroups,
				newEndpointSecurityGroups,

				func(lc cell.Lifecycle, c client.Clientset, mp workqueue.MetricsProvider) resource.Resource[*k8sTypes.CiliumEndpoint] {
					lw := utils.ListerWatcherFromTyped[*ciliumv2.CiliumEndpointList](c.CiliumV2().CiliumEndpoints(slim_corev1.NamespaceAll))
					return resource.New[*k8sTypes.CiliumEndpoint](lc, lw, mp,
						resource.WithLazyTransform(func() runtime.Object {
							return &ciliumv2.CiliumEndpoint{}
						}, k8s.TransformToCiliumEndpoint),
					)
				},
				func() tunnel.Config {
					return tunnel.NewTestConfig(tunnel.VXLAN)
				},
				func() promise.Promise[synced.CRDSync] {
					resolve, p := promise.New[synced.CRDSync]()
					resolve.Resolve(synced.CRDSync{})
					return p
				},
				func() cmtypes.ClusterInfo {
					return cmtypes.ClusterInfo{}
				},
				func() promise.Promise[endpointstate.Restorer] {
					resolve, p := promise.New[endpointstate.Restorer]()
					resolve.Resolve(noopRestorer{})
					return p
				},
				func() (endpointLookupProvider, uhive.ScriptCmdsOut) {
					f := newFakeEndpointsLookup()
					cmds := uhive.NewScriptCmds(map[string]script.Cmd{
						"test/ep-upsert": f.epUpsertCmd(),
						"test/ep-delete": f.epDeleteCmd(),
					})
					return f, cmds
				},
			),

			cell.Invoke(func(lns *node.LocalNodeStore) {
				lns.Update(func(ln *node.LocalNode) {
					ln.Node.IPAddresses = []nodeTypes.Address{{
						Type: addressing.NodeInternalIP,
						IP:   net.ParseIP(*nodeIP),
					}}
					ln.Local.UnderlayProtocol = tunnel.IPv4
				})
			},
				(*securityGroups).registerK8sReflector,
				(*endpointSecurityGroups).registerReconciler,
			),
		)

		hive.AddConfigOverride(h, func(c *evpnConfig.Config) {
			c.CommonConfig.Enabled = true
			c.SecurityGroupTagsEnabled = true
			c.DefaultSecurityGroupID = *defaultGroupIP
		})
		t.Cleanup(func() {
			assert.NoError(t, h.Stop(log, context.Background()))
		})

		cmds, err := h.ScriptCommands(log)
		require.NoError(t, err, "ScriptCommands")
		maps.Insert(cmds, maps.All(script.DefaultCmds()))

		return &script.Engine{Cmds: cmds}
	}, []string{}, "testdata/*.txtar")
}

type noopRestorer struct{}

func (noopRestorer) WaitForEndpointRestoreWithoutRegeneration(context.Context) error { return nil }
func (noopRestorer) WaitForEndpointRestore(context.Context) error                    { return nil }
func (noopRestorer) WaitForInitialPolicy(context.Context) error                      { return nil }

type fakeEndpointsLookup struct {
	mu    lock.RWMutex
	byCEP map[string]fakeEndpointMetadata
}

func newFakeEndpointsLookup() *fakeEndpointsLookup {
	return &fakeEndpointsLookup{
		byCEP: make(map[string]fakeEndpointMetadata),
	}
}

func (f *fakeEndpointsLookup) epUpsertCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Insert or update CEP-name metadata in the fake endpoint manager",
			Args:    "<namespace/name> <endpoint-id> <is-privnet-enabled>",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 3 {
				return nil, fmt.Errorf("%w: expected <namespace/name> <endpoint-id> <is-privnet-enabled>", script.ErrUsage)
			}
			id, err := strconv.ParseUint(args[1], 10, 16)
			if err != nil {
				return nil, err
			}
			isPrivnet, err := strconv.ParseBool(args[2])
			if err != nil {
				return nil, err
			}
			f.mu.Lock()
			f.byCEP[args[0]] = fakeEndpointMetadata{id: uint16(id), isPrivnet: isPrivnet}
			f.mu.Unlock()
			return nil, nil
		},
	)
}

func (f *fakeEndpointsLookup) epDeleteCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Delete a CEP-name metadata from the fake endpoint manager",
			Args:    "<namespace/name>",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("%w: expected <namespace/name>", script.ErrUsage)
			}
			f.mu.Lock()
			delete(f.byCEP, args[0])
			f.mu.Unlock()
			return nil, nil
		},
	)
}

func (f *fakeEndpointsLookup) lookupEndpointMetadataByName(name string) (uint16, bool) {
	f.mu.RLock()
	ep := f.byCEP[name]
	f.mu.RUnlock()
	return ep.id, ep.isPrivnet
}
