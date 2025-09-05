//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package bfd

import (
	"context"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/util/workqueue"

	bgpv2config "github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sclient "github.com/cilium/cilium/pkg/k8s/client"
	client_ciliumv2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	client_isovalentv1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1"
	client_isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	k8sfake "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/time"
)

var (
	TestTimeout = 5 * time.Second
)

type fixture struct {
	hive          *hive.Hive
	fakeClientSet *k8sfake.FakeClientset

	ciliumNodeClient            client_ciliumv2.CiliumNodeInterface
	bgpClusterConfigClient      client_isovalentv1.IsovalentBGPClusterConfigInterface
	bgpPeerConfigClient         client_isovalentv1.IsovalentBGPPeerConfigInterface
	bfdNodeConfigClient         client_isovalentv1alpha1.IsovalentBFDNodeConfigInterface
	bfdNodeConfigOverrideClient client_isovalentv1alpha1.IsovalentBFDNodeConfigOverrideInterface
}

func newFixture(t *testing.T, ctx context.Context, req *require.Assertions) *fixture {
	f := &fixture{}
	f.fakeClientSet, _ = k8sfake.NewFakeClientset(hivetest.Logger(t))

	f.ciliumNodeClient = f.fakeClientSet.CiliumFakeClientset.CiliumV2().CiliumNodes()
	f.bgpClusterConfigClient = f.fakeClientSet.CiliumFakeClientset.IsovalentV1().IsovalentBGPClusterConfigs()
	f.bgpPeerConfigClient = f.fakeClientSet.IsovalentV1().IsovalentBGPPeerConfigs()
	f.bfdNodeConfigClient = f.fakeClientSet.CiliumFakeClientset.IsovalentV1alpha1().IsovalentBFDNodeConfigs()
	f.bfdNodeConfigOverrideClient = f.fakeClientSet.CiliumFakeClientset.IsovalentV1alpha1().IsovalentBFDNodeConfigOverrides()

	f.hive = hive.New(
		Cell,

		cell.Config(bgpv2config.Config{
			Enabled:             true,
			StatusReportEnabled: true,
		}),
		cell.Provide(
			k8s.IsovalentBGPClusterConfigResource,
			k8s.IsovalentBGPPeerConfigResource,
		),

		cell.Provide(func(lc cell.Lifecycle, c k8sclient.Clientset, mp workqueue.MetricsProvider) resource.Resource[*ciliumv2.CiliumNode] {
			return resource.New[*ciliumv2.CiliumNode](
				lc, utils.ListerWatcherFromTyped[*ciliumv2.CiliumNodeList](
					c.CiliumV2().CiliumNodes(),
				), mp,
			)
		}),

		cell.Provide(func() k8sclient.Clientset {
			return f.fakeClientSet
		}),
	)

	hive.AddConfigOverride(f.hive, func(cfg *types.BFDConfig) { cfg.BFDEnabled = true })

	return f
}
