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
		cfg := &config.BPFLXCEnterprise{
			PrivnetUnknownSecID: uint32(identity.ReservedPrivnetUnknownFlow),
		}

		if l.privnetConfig.Enabled {
			networkProps, ok := pnendpoints.ExtractEndpointProperties(ep)
			if ok {
				cfg.PrivnetEnable = true
				cfg.PrivnetBridgeEnable = l.privnetConfig.EnabledAsBridge()

				if addr, _ := networkProps.NetworkIPv6(); addr.IsValid() {
					cfg.PrivnetIPv6 = addr.As16()
				}
			}
		}

		return cfg
	})
}

func (l *EnterpriseLoader) registerOverlayConfig() {
	overlayConfigs.register(func(lnc *datapath.LocalNodeConfiguration, link netlink.Link) any {
		return &config.BPFOverlayEnterprise{
			PrivnetEnable:       l.privnetConfig.Enabled,
			PrivnetBridgeEnable: l.privnetConfig.EnabledAsBridge(),
			PrivnetUnknownSecID: uint32(identity.ReservedPrivnetUnknownFlow),
		}
	})
}

func (l *EnterpriseLoader) registerNetdevConfig() {
	netdevConfigs.register(func(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration, link netlink.Link, _ netip.Addr, _ netip.Addr) any {
		return &config.BPFHostEnterprise{
			PrivnetEnable:       l.privnetConfig.Enabled,
			PrivnetBridgeEnable: l.privnetConfig.EnabledAsBridge(),
			PrivnetUnknownSecID: uint32(identity.ReservedPrivnetUnknownFlow),
		}
	})
}
