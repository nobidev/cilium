// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package config

import (
	"github.com/vishvananda/netlink"

	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	privnetConfig "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
)

// EvpnBase returns a [BPFEvpnBase].
func EvpnBase(lnc *datapath.LocalNodeConfiguration, link netlink.Link) any {
	cfg := NewBPFEvpnBase(NodeConfig(lnc))

	cfg.InterfaceIfIndex = uint32(link.Attrs().Index)
	cfg.InterfaceMAC = mac.MAC(link.Attrs().HardwareAddr).As8()

	cfg.AllowICMPFragNeeded = option.Config.AllowICMPFragNeeded
	cfg.EnableICMPRule = option.Config.EnableICMPRules
	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols

	return cfg
}

// EvpnEnterprise returns a [BPFEvpnEnterprise].
func EvpnEnterprise(evpnCfg evpnConfig.Config, privnetCfg privnetConfig.Config) any {
	cfg := NewBPFEvpnEnterprise()

	cfg.EvpnEnable = evpnCfg.Enabled

	cfg.PrivnetEnable = privnetCfg.Enabled
	cfg.PrivnetBridgeEnable = privnetCfg.EnabledAsBridge()
	cfg.PrivnetUnknownSecID = uint32(identity.ReservedPrivnetUnknownFlow)

	return cfg
}
