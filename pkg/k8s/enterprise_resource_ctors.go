//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package k8s

import (
	"github.com/cilium/hive/cell"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	isovalent_api_v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
)

func IsovalentFQDNGroup(lc cell.Lifecycle, cs client.Clientset, mp workqueue.MetricsProvider) (resource.Resource[*isovalent_api_v1alpha1.IsovalentFQDNGroup], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentFQDNGroupList](cs.IsovalentV1alpha1().IsovalentFQDNGroups())
	return resource.New[*isovalent_api_v1alpha1.IsovalentFQDNGroup](lc, lw, mp, resource.WithMetric("IsovalentFQDNGroup")), nil
}

func IsovalentBGPClusterConfigResource(lc cell.Lifecycle, c client.Clientset, mp workqueue.MetricsProvider, bgpConfig config.Config) resource.Resource[*isovalent_api_v1.IsovalentBGPClusterConfig] {
	if !c.IsEnabled() || !bgpConfig.Enabled {
		return nil
	}

	return resource.New[*isovalent_api_v1.IsovalentBGPClusterConfig](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1.IsovalentBGPClusterConfigList](
			c.IsovalentV1().IsovalentBGPClusterConfigs(),
		), mp, resource.WithMetric("IsovalentBGPClusterConfig"))
}

func IsovalentBGPPeerConfigResource(lc cell.Lifecycle, c client.Clientset, mp workqueue.MetricsProvider, bgpConfig config.Config) resource.Resource[*isovalent_api_v1.IsovalentBGPPeerConfig] {
	if !c.IsEnabled() || !bgpConfig.Enabled {
		return nil
	}

	return resource.New[*isovalent_api_v1.IsovalentBGPPeerConfig](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1.IsovalentBGPPeerConfigList](
			c.IsovalentV1().IsovalentBGPPeerConfigs(),
		), mp, resource.WithMetric("IsovalentBGPPeerConfig"))
}

func IsovalentBGPAdvertisementResource(lc cell.Lifecycle, c client.Clientset, mp workqueue.MetricsProvider, bgpConfig config.Config) resource.Resource[*isovalent_api_v1.IsovalentBGPAdvertisement] {
	if !c.IsEnabled() || !bgpConfig.Enabled {
		return nil
	}

	return resource.New[*isovalent_api_v1.IsovalentBGPAdvertisement](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1.IsovalentBGPAdvertisementList](
			c.IsovalentV1().IsovalentBGPAdvertisements(),
		), mp, resource.WithMetric("IsovalentBGPAdvertisement"))
}

func IsovalentBGPNodeConfigResource(lc cell.Lifecycle, c client.Clientset, mp workqueue.MetricsProvider, bgpConfig config.Config) resource.Resource[*isovalent_api_v1.IsovalentBGPNodeConfig] {
	if !c.IsEnabled() || !bgpConfig.Enabled {
		return nil
	}

	return resource.New[*isovalent_api_v1.IsovalentBGPNodeConfig](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1.IsovalentBGPNodeConfigList](
			c.IsovalentV1().IsovalentBGPNodeConfigs(),
		), mp, resource.WithMetric("IsovalentBGPNodeConfig"))
}

func IsovalentBGPNodeConfigOverrideResource(lc cell.Lifecycle, c client.Clientset, mp workqueue.MetricsProvider, bgpConfig config.Config) resource.Resource[*isovalent_api_v1.IsovalentBGPNodeConfigOverride] {
	if !c.IsEnabled() || !bgpConfig.Enabled {
		return nil
	}

	return resource.New[*isovalent_api_v1.IsovalentBGPNodeConfigOverride](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1.IsovalentBGPNodeConfigOverrideList](
			c.IsovalentV1().IsovalentBGPNodeConfigOverrides(),
		), mp, resource.WithMetric("IsovalentBGPNodeConfigOverride"))
}

func IsovalentBGPPolicyResource(lc cell.Lifecycle, c client.Clientset, mp workqueue.MetricsProvider, bgpConfig config.Config) resource.Resource[*isovalent_api_v1.IsovalentBGPPolicy] {
	if !c.IsEnabled() || !bgpConfig.Enabled {
		return nil
	}

	return resource.New[*isovalent_api_v1.IsovalentBGPPolicy](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1.IsovalentBGPPolicyList](
			c.IsovalentV1().IsovalentBGPPolicies(),
		), mp, resource.WithMetric("IsovalentBGPPolicy"))
}

func IsovalentBGPVRFConfigResource(lc cell.Lifecycle, c client.Clientset, mp workqueue.MetricsProvider, bgpConfig config.Config) resource.Resource[*isovalent_api_v1alpha1.IsovalentBGPVRFConfig] {
	if !c.IsEnabled() || !bgpConfig.Enabled {
		return nil
	}

	return resource.New[*isovalent_api_v1alpha1.IsovalentBGPVRFConfig](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentBGPVRFConfigList](
			c.IsovalentV1alpha1().IsovalentBGPVRFConfigs(),
		), mp, resource.WithMetric("IsovalentBGPVRFConfig"))
}

func IsovalentBFDProfileResource(lc cell.Lifecycle, c client.Clientset, mp workqueue.MetricsProvider, cfg types.BFDConfig) resource.Resource[*isovalent_api_v1alpha1.IsovalentBFDProfile] {
	if !cfg.BFDEnabled {
		return nil
	}

	return resource.New[*isovalent_api_v1alpha1.IsovalentBFDProfile](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentBFDProfileList](
			c.IsovalentV1alpha1().IsovalentBFDProfiles(),
		), mp, resource.WithMetric("IsovalentBFDProfile"))
}

func IsovalentBFDNodeConfigResource(lc cell.Lifecycle, c client.Clientset, mp workqueue.MetricsProvider, cfg types.BFDConfig) resource.Resource[*isovalent_api_v1alpha1.IsovalentBFDNodeConfig] {
	if !cfg.BFDEnabled {
		return nil
	}

	return resource.New[*isovalent_api_v1alpha1.IsovalentBFDNodeConfig](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentBFDNodeConfigList](
			c.IsovalentV1alpha1().IsovalentBFDNodeConfigs(),
		), mp, resource.WithMetric("IsovalentBFDNodeConfig"))
}

func IsovalentBFDNodeConfigOverrideResource(lc cell.Lifecycle, c client.Clientset, mp workqueue.MetricsProvider, cfg types.BFDConfig) resource.Resource[*isovalent_api_v1alpha1.IsovalentBFDNodeConfigOverride] {
	if !cfg.BFDEnabled {
		return nil
	}

	return resource.New[*isovalent_api_v1alpha1.IsovalentBFDNodeConfigOverride](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentBFDNodeConfigOverrideList](
			c.IsovalentV1alpha1().IsovalentBFDNodeConfigOverrides(),
		), mp, resource.WithMetric("IsovalentBFDNodeConfigOverride"))
}

func IsovalentSRv6LocatorPoolResource(lc cell.Lifecycle, c client.Clientset, mp workqueue.MetricsProvider, bgpConfig config.Config, dc *option.DaemonConfig) resource.Resource[*isovalent_api_v1alpha1.IsovalentSRv6LocatorPool] {
	if !c.IsEnabled() || !bgpConfig.Enabled || !dc.EnableSRv6 {
		return nil
	}
	return resource.New[*isovalent_api_v1alpha1.IsovalentSRv6LocatorPool](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentSRv6LocatorPoolList](
			c.IsovalentV1alpha1().IsovalentSRv6LocatorPools(),
		), mp, resource.WithMetric("IsovalentSRv6LocatorPool"))
}

func IsovalentVRFResource(lc cell.Lifecycle, dc *option.DaemonConfig, bgpConfig config.Config, c client.Clientset, mp workqueue.MetricsProvider) resource.Resource[*isovalent_api_v1alpha1.IsovalentVRF] {
	if !c.IsEnabled() || !dc.EnableSRv6 || !bgpConfig.Enabled {
		return nil
	}
	return resource.New[*isovalent_api_v1alpha1.IsovalentVRF](
		lc, utils.ListerWatcherFromTyped[*isovalent_api_v1alpha1.IsovalentVRFList](
			c.IsovalentV1alpha1().IsovalentVRFs(),
		), mp, resource.WithMetric("IsovalentVRFResource"))
}

func IsovalentNetworkPolicyResource(params CiliumResourceParams, mp workqueue.MetricsProvider, opts ...func(*metav1.ListOptions)) (resource.Resource[*isovalent_api_v1.IsovalentNetworkPolicy], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*isovalent_api_v1.IsovalentNetworkPolicyList](params.ClientSet.IsovalentV1().IsovalentNetworkPolicies("")),
		opts...,
	)
	return resource.New[*isovalent_api_v1.IsovalentNetworkPolicy](params.Lifecycle, lw, mp, resource.WithMetric("IsovalentNetworkPolicy"), resource.WithCRDSync(params.CRDSyncPromise)), nil
}

func IsovalentClusterwideNetworkPolicyResource(params CiliumResourceParams, mp workqueue.MetricsProvider, opts ...func(*metav1.ListOptions)) (resource.Resource[*isovalent_api_v1.IsovalentClusterwideNetworkPolicy], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*isovalent_api_v1.IsovalentClusterwideNetworkPolicyList](params.ClientSet.IsovalentV1().IsovalentClusterwideNetworkPolicies()),
		opts...,
	)
	return resource.New[*isovalent_api_v1.IsovalentClusterwideNetworkPolicy](params.Lifecycle, lw, mp, resource.WithMetric("IsovalentClusterwideNetworkPolicy"), resource.WithCRDSync(params.CRDSyncPromise)), nil
}
