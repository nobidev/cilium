//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"github.com/cilium/cilium/daemon/cmd"
	_ "github.com/cilium/cilium/enterprise/fips"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
)

func main() {
	agentHive := hive.New(
		EnterpriseAgent,
	)

	// Force disable the new load-balancing control-plane until
	// the enterprise code has migrated over to it.
	hive.AddConfigOverride(
		agentHive,
		func(cfg *experimental.Config) { cfg.EnableExperimentalLB = false },
	)

	hiveFn := func() *hive.Hive {
		return agentHive
	}

	agentCmd := cmd.NewAgentCmd(hiveFn)
	cmd.Execute(agentCmd)
}
