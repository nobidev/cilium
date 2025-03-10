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
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"bgp-enterprise-operator",
	"BGP Control Plane Operator",

	cell.Provide(
		k8s.IsovalentBGPClusterConfigResource,
		k8s.IsovalentBGPPeerConfigResource,
		k8s.IsovalentBGPAdvertisementResource,
		k8s.IsovalentBGPNodeConfigResource,
		k8s.IsovalentBGPNodeConfigOverrideResource,
		k8s.IsovalentVRFResource,
		k8s.IsovalentBGPVRFConfigResource,
	),

	cell.ProvidePrivate(
		newSecretResource,
		k8s.IsovalentBFDProfileResource,
		store.NewBGPCPResourceStore[*v1.IsovalentBGPClusterConfig],
		store.NewBGPCPResourceStore[*v1.IsovalentBGPPeerConfig],
		store.NewBGPCPResourceStore[*v1.IsovalentBGPAdvertisement],
		store.NewBGPCPResourceStore[*v1.IsovalentBGPNodeConfigOverride],
		store.NewBGPCPResourceStore[*v1alpha1.IsovalentVRF],
		store.NewBGPCPResourceStore[*v1alpha1.IsovalentBGPVRFConfig],
		store.NewBGPCPResourceStore[*cilium_v2.CiliumNode],
	),

	cell.ProvidePrivate(
		// Provide v2alpha1 OSS resources for the enterprise operator,
		// as the OSS code is using v2 version already.
		// TODO: Remove after migration of enterprise code to v2 OSS APIs.
		newV2alpha1BGPClusterConfigResource,
		newV2alpha1BGPPeerConfigResource,
		newV2alpha1BGPAdvertisementResource,
		newV2alpha1BGPNodeConfigResource,
		newV2alpha1BGPNodeConfigOverrideResource,
	),

	cell.ProvidePrivate(signaler.NewBGPCPSignaler),

	cell.Config(config.DefaultConfig),
	metrics.Metric(newBGPOperatorMetrics),

	cell.Invoke(
		RegisterBGPResourceMapper,
		registerPeerConfigStatusReconciler,
	),
)

func newSecretResource(lc cell.Lifecycle, c client.Clientset, cc config.Config, dc *option.DaemonConfig) resource.Resource[*slim_core_v1.Secret] {
	if !c.IsEnabled() || !cc.Enabled {
		return nil
	}
	if dc.BGPSecretsNamespace == "" {
		return nil
	}
	return resource.New[*slim_core_v1.Secret](
		lc, utils.ListerWatcherFromTyped(
			c.Slim().CoreV1().Secrets(dc.BGPSecretsNamespace),
		))
}

func newV2alpha1BGPClusterConfigResource(lc cell.Lifecycle, c client.Clientset, dc *option.DaemonConfig) resource.Resource[*v2alpha1.CiliumBGPClusterConfig] {
	if !c.IsEnabled() {
		return nil
	}
	return resource.New[*v2alpha1.CiliumBGPClusterConfig](
		lc, utils.ListerWatcherFromTyped[*v2alpha1.CiliumBGPClusterConfigList](
			c.CiliumV2alpha1().CiliumBGPClusterConfigs(),
		), resource.WithMetric("CiliumBGPClusterConfig"))
}

func newV2alpha1BGPPeerConfigResource(lc cell.Lifecycle, c client.Clientset, dc *option.DaemonConfig) resource.Resource[*v2alpha1.CiliumBGPPeerConfig] {
	if !c.IsEnabled() {
		return nil
	}
	return resource.New[*v2alpha1.CiliumBGPPeerConfig](
		lc, utils.ListerWatcherFromTyped[*v2alpha1.CiliumBGPPeerConfigList](
			c.CiliumV2alpha1().CiliumBGPPeerConfigs(),
		), resource.WithMetric("CiliumBGPPeerConfig"))
}

func newV2alpha1BGPAdvertisementResource(lc cell.Lifecycle, c client.Clientset, dc *option.DaemonConfig) resource.Resource[*v2alpha1.CiliumBGPAdvertisement] {
	if !c.IsEnabled() {
		return nil
	}
	return resource.New[*v2alpha1.CiliumBGPAdvertisement](
		lc, utils.ListerWatcherFromTyped[*v2alpha1.CiliumBGPAdvertisementList](
			c.CiliumV2alpha1().CiliumBGPAdvertisements(),
		), resource.WithMetric("CiliumBGPAdvertisement"))
}

func newV2alpha1BGPNodeConfigResource(lc cell.Lifecycle, c client.Clientset, dc *option.DaemonConfig) resource.Resource[*v2alpha1.CiliumBGPNodeConfig] {
	if !c.IsEnabled() {
		return nil
	}
	return resource.New[*v2alpha1.CiliumBGPNodeConfig](
		lc, utils.ListerWatcherFromTyped[*v2alpha1.CiliumBGPNodeConfigList](
			c.CiliumV2alpha1().CiliumBGPNodeConfigs(),
		), resource.WithMetric("CiliumBGPNodeConfig"))
}

func newV2alpha1BGPNodeConfigOverrideResource(lc cell.Lifecycle, c client.Clientset, dc *option.DaemonConfig) resource.Resource[*v2alpha1.CiliumBGPNodeConfigOverride] {
	if !c.IsEnabled() {
		return nil
	}
	return resource.New[*v2alpha1.CiliumBGPNodeConfigOverride](
		lc, utils.ListerWatcherFromTyped[*v2alpha1.CiliumBGPNodeConfigOverrideList](
			c.CiliumV2alpha1().CiliumBGPNodeConfigOverrides(),
		), resource.WithMetric("CiliumBGPNodeConfigOverride"))
}
