//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressmapha

import (
	"github.com/spf13/pflag"

	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"egressmaps",
	"Egressmaps provide access to the egress gateway datapath maps",
	cell.Config(DefaultPolicyConfig),
	cell.Provide(createPolicyMapFromDaemonConfig),
	cell.Provide(createPolicyMapV2FromDaemonConfig),
	cell.Provide(createCtMapFromDaemonConfig),
)

type PolicyConfig struct {
	// EgressGatewayHAPolicyMapMax is the maximum number of entries
	// allowed in the BPF egress gateway policy map.
	EgressGatewayHAPolicyMapMax int
}

var DefaultPolicyConfig = PolicyConfig{
	EgressGatewayHAPolicyMapMax: 1 << 14,
}

func (def PolicyConfig) Flags(flags *pflag.FlagSet) {
	flags.Int("egress-gateway-ha-policy-map-max", def.EgressGatewayHAPolicyMapMax, "Maximum number of entries in egress gatewa HA policy map")
}
