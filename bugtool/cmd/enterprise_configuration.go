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

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/cilium/pkg/defaults"
)

func init() {
	ExtraCommands = append(ExtraCommands, enterpriseCommands)
}

func enterpriseCommands(confDir string, _ string) []string {
	var commands []string

	bpfMapsPath := []string{
		"tc/globals/cilium_egress_gw_ha_policy_v4",
		"tc/globals/cilium_egress_gw_ha_policy_v4_v2",
		"tc/globals/cilium_egress_gw_ha_ct_v4",
		"tc/globals/cilium_egress_gw_standalone_v4",
		"tc/globals/cilium_encryption_policy_map",
	}

	infoCommands := []string{
		"cilium-dbg bpf egress-ha list",
		"cilium-dbg bpf egress-ha ct list",
		"cilium-dbg bpf egress-ha standalone list",
		"cilium-dbg bpf privnet fib list",
		"cilium-dbg bpf privnet pip list",
		"cilium-dbg shell -- privnet/status --color=false",
		"cilium-dbg shell -- privnet/status -o=json",
	}

	commands = append(commands, bpfMapDumpCommands(bpfMapsPath)...)
	commands = append(commands, infoCommands...)
	commands = append(commands, fqdnProxyCommands()...)

	return commands
}

func fqdnProxyCommands() []string {
	shellSockPath := filepath.Join(defaults.RuntimePath, "dnsproxy-shell.sock")
	shellCmd := fmt.Sprintf("cilium-dbg shell --shell-sock-path %s -- ", shellSockPath)

	// Ensure that the fqdn proxy shell server is listening.
	if _, err := os.Stat(shellSockPath); os.IsNotExist(err) {
		return nil
	}

	return []string{
		shellCmd + "dnsproxy/config -o=json",
		shellCmd + "dnsproxy/rules -o=json",
		shellCmd + "dnsproxy/bpfipcache",
		shellCmd + "dnsproxy/selectors",
		shellCmd + "dnsproxy/identities",
		shellCmd + "dnsproxy/endpoints",
		shellCmd + "dnsproxy/iplist",
	}
}
