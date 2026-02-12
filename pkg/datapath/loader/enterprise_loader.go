// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package loader

import (
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/vishvananda/netlink"

	pnconfig "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	pnendpoints "github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	"github.com/cilium/cilium/pkg/datapath/config"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/option"
)

// EnterpriseCell provides the enterprise-specific loader config hooks.
var EnterpriseCell = cell.Module(
	"enterprise-loader",
	"Enterprise Loader",

	cell.Provide(newEnterpriseLoader),

	cell.Invoke(
		(*EnterpriseLoader).registerEndpointConfig,
		(*EnterpriseLoader).registerOverlayConfig,
		(*EnterpriseLoader).registerNetdevConfig,
		(*EnterpriseLoader).registerWireguardConfig,
	),
)

type EnterpriseLoader struct {
	privnetConfig pnconfig.Config
}

func newEnterpriseLoader(in struct {
	cell.In

	PrivnetConfig pnconfig.Config
}) *EnterpriseLoader {
	return &EnterpriseLoader{
		privnetConfig: in.PrivnetConfig,
	}
}

func (l *EnterpriseLoader) registerEndpointConfig() {
	epConfigs.register(func(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration) any {
		cfg := config.NewBPFLXCEnterprise()

		cfg.PrivnetUnknownSecID = uint32(identity.ReservedPrivnetUnknownFlow)

		if l.privnetConfig.Enabled {
			_, ok := pnendpoints.ExtractEndpointProperties(ep)
			if ok {
				cfg.PrivnetEnable = true
				cfg.PrivnetBridgeEnable = l.privnetConfig.EnabledAsBridge()
			}
		}

		return cfg
	})
}

func (l *EnterpriseLoader) registerOverlayConfig() {
	overlayConfigs.register(func(lnc *datapath.LocalNodeConfiguration, link netlink.Link) any {
		cfg := config.NewBPFOverlayEnterprise()

		cfg.PrivnetEnable = l.privnetConfig.Enabled
		cfg.PrivnetBridgeEnable = l.privnetConfig.EnabledAsBridge()
		cfg.PrivnetUnknownSecID = uint32(identity.ReservedPrivnetUnknownFlow)

		cfg.AllowICMPFragNeeded = option.Config.AllowICMPFragNeeded
		cfg.EnableICMPRule = option.Config.EnableICMPRules
		cfg.EnablePolicyAccounting = lnc.EnablePolicyAccounting

		return cfg
	})
}

func (l *EnterpriseLoader) registerNetdevConfig() {
	netdevConfigs.register(func(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration, link netlink.Link, _ netip.Addr, _ netip.Addr) any {
		cfg := config.NewBPFHostEnterprise()

		cfg.PrivnetEnable = l.privnetConfig.Enabled
		cfg.PrivnetBridgeEnable = l.privnetConfig.EnabledAsBridge()
		cfg.PrivnetUnknownSecID = uint32(identity.ReservedPrivnetUnknownFlow)

		return cfg
	})
}

func (l *EnterpriseLoader) registerWireguardConfig() {
	wireguardConfigs.register(func(lnc *datapath.LocalNodeConfiguration, link netlink.Link) any {
		cfg := config.NewBPFWireguardEnterprise()

		cfg.PrivnetEnable = l.privnetConfig.Enabled
		cfg.PrivnetBridgeEnable = l.privnetConfig.EnabledAsBridge()
		cfg.PrivnetUnknownSecID = uint32(identity.ReservedPrivnetUnknownFlow)

		return cfg
	})
}
