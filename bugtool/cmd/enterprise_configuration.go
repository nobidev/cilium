//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package cmd

func init() {
	ExtraCommands = append(ExtraCommands, enterpriseCommands)
}

func enterpriseCommands(confDir string, _ string) []string {
	bpfMapsPath := []string{
		"tc/globals/cilium_egress_gw_ha_policy_v4",
		"tc/globals/cilium_egress_gw_ha_policy_v4_v2",
		"tc/globals/cilium_egress_gw_ha_ct_v4",
		"tc/globals/cilium_egress_gw_standalone_v4",
		"tc/globals/cilium_encryption_policy_map",
	}
	bpfCommands := bpfMapDumpCommands(bpfMapsPath)

	infoCommands := []string{
		"cilium-dbg bpf egress-ha list",
		"cilium-dbg bpf egress-ha ct list",
		"cilium-dbg bpf egress-ha standalone list",
		"cilium-dbg bpf privnet fib list",
		"cilium-dbg bpf privnet pip list",
		"cilium-dbg shell -- privnet/status --color=false",
		"cilium-dbg shell -- privnet/status -o=json",
	}
	return append(bpfCommands, infoCommands...)
}
