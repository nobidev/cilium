// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bgpv2

import (
	"context"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/enterprise/operator/pkg/bfd"
	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	bfdTypes "github.com/cilium/cilium/enterprise/pkg/bfd/types"
	operatorK8s "github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/hive"
	healthTypes "github.com/cilium/cilium/pkg/hive/health/types"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	cilium_client_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	isovalent_client_v1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1"
	isovalent_client_v1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	k8s_fake "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var (
	TestTimeout = 10 * time.Second
)

type fixture struct {
	hive          *hive.Hive
	fakeClientSet *k8s_fake.FakeClientset

	isoClusterClient       isovalent_client_v1.IsovalentBGPClusterConfigInterface
	isoPeerConfClient      isovalent_client_v1.IsovalentBGPPeerConfigInterface
	isoAdvertClient        isovalent_client_v1.IsovalentBGPAdvertisementInterface
	isoBGPNodeConfClient   isovalent_client_v1.IsovalentBGPNodeConfigInterface
	isoBGPNodeConfORClient isovalent_client_v1.IsovalentBGPNodeConfigOverrideInterface
	isoVrfClient           isovalent_client_v1alpha1.IsovalentVRFInterface
	isoBGPVrfClient        isovalent_client_v1alpha1.IsovalentBGPVRFConfigInterface

	// oss clients
	ossClusterClient    cilium_client_v2.CiliumBGPClusterConfigInterface
	ossPeerConfClient   cilium_client_v2.CiliumBGPPeerConfigInterface
	ossAdvertClient     cilium_client_v2.CiliumBGPAdvertisementInterface
	ossNodeConfClient   cilium_client_v2.CiliumBGPNodeConfigInterface
	ossNodeConfORClient cilium_client_v2.CiliumBGPNodeConfigOverrideInterface

	// node client
	nodeClient cilium_client_v2.CiliumNodeInterface

	// db client
	db          *statedb.DB
	healthTable statedb.Table[healthTypes.Status]
}

type fixtureConfig struct {
	enableBFD          bool
	enableStatusReport bool
}

func newFixture(t *testing.T, ctx context.Context, req *require.Assertions, fc fixtureConfig) *fixture {
	f := &fixture{}
	f.fakeClientSet, _ = k8s_fake.NewFakeClientset(hivetest.Logger(t))

	// enterprise clients
	f.isoClusterClient = f.fakeClientSet.IsovalentV1().IsovalentBGPClusterConfigs()
	f.isoPeerConfClient = f.fakeClientSet.IsovalentV1().IsovalentBGPPeerConfigs()
	f.isoAdvertClient = f.fakeClientSet.IsovalentV1().IsovalentBGPAdvertisements()
	f.isoBGPNodeConfClient = f.fakeClientSet.IsovalentV1().IsovalentBGPNodeConfigs()
	f.isoBGPNodeConfORClient = f.fakeClientSet.IsovalentV1().IsovalentBGPNodeConfigOverrides()
	f.isoVrfClient = f.fakeClientSet.IsovalentV1alpha1().IsovalentVRFs()
	f.isoBGPVrfClient = f.fakeClientSet.IsovalentV1alpha1().IsovalentBGPVRFConfigs()

	// oss clients
	f.ossClusterClient = f.fakeClientSet.CiliumV2().CiliumBGPClusterConfigs()
	f.ossPeerConfClient = f.fakeClientSet.CiliumV2().CiliumBGPPeerConfigs()
	f.ossAdvertClient = f.fakeClientSet.CiliumV2().CiliumBGPAdvertisements()
	f.ossNodeConfClient = f.fakeClientSet.CiliumV2().CiliumBGPNodeConfigs()
	f.ossNodeConfORClient = f.fakeClientSet.CiliumV2().CiliumBGPNodeConfigOverrides()

	// node client
	f.nodeClient = f.fakeClientSet.CiliumV2().CiliumNodes()

	f.hive = hive.New(
		cell.Provide(
			k8s.CiliumBGPPeerConfigResource,
			k8s.CiliumBGPAdvertisementResource,
			k8s.CiliumBGPNodeConfigResource,
			operatorK8s.CiliumBGPClusterConfigResource,
			operatorK8s.CiliumBGPNodeConfigOverrideResource,
		),

		cell.Provide(func(lc cell.Lifecycle, c k8s_client.Clientset, mp workqueue.MetricsProvider) resource.Resource[*cilium_v2.CiliumNode] {
			return resource.New[*cilium_v2.CiliumNode](
				lc, utils.ListerWatcherFromTyped(
					c.CiliumV2().CiliumNodes(),
				), mp,
			)
		}),

		cell.Provide(
			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					EnableBGPControlPlane: true,
					EnableSRv6:            true,
					BGPSecretsNamespace:   "kube-system",
				}
			},
		),

		cell.Provide(func() k8s_client.Clientset {
			return f.fakeClientSet
		}),

		cell.Invoke(
			func(db *statedb.DB, h statedb.Table[healthTypes.Status]) {
				f.db = db
				f.healthTable = h
			},
		),

		bfd.Cell,

		Cell,
	)

	hive.AddConfigOverride(f.hive, func(cfg *config.Config) {
		cfg.Enabled = true
		cfg.StatusReportEnabled = fc.enableStatusReport
	})
	hive.AddConfigOverride(f.hive, func(cfg *bfdTypes.BFDConfig) { cfg.BFDEnabled = fc.enableBFD })

	return f
}
