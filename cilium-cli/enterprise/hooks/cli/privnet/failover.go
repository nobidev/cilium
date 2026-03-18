// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package privnet

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type failover struct {
	scenario
	target NodeName
}

// NewFailover returns a scenario that disrupts the connectivity to the target
// INB node, and validates that workload nodes failover correctly. Then, it
// restores the connectivity to the INB, and asserts again that the INB status
// on workload nodes converges.
func NewFailover(t *TestRun, target NodeName) Scenario {
	name := fmt.Sprintf("failover-%s", target)
	return &failover{
		scenario: scenario{t: t, name: name},
		target:   target,
	}
}

func (f *failover) Run(ctx context.Context, _ Expectation, _ ...features.IPFamily) {
	var clusterAgents = slices.Collect(maps.Values(f.t.ciliumPodsCluster))
	if len(clusterAgents) == 0 {
		f.fail(features.IPFamilyAny, "no Cilium agent found hosted on workload nodes")
		return
	}

	targetAgent, ok := f.t.ciliumPodsINBs[f.target]
	if !ok {
		f.fail(features.IPFamilyAny, "no Cilium agent found hosted on INB node %s", f.target)
		return
	}

	var initial = make(map[NodeName]activeINBs)
	for _, agent := range clusterAgents {
		inbs, err := f.t.getINBs(ctx, agent, f.t.assertSteadyState())
		if err != nil {
			f.fail(features.IPFamilyAny, "node %s: %v", agent.NodeName(), err)
			return
		}

		initial[NodeName(agent.NodeName())] = inbs
	}

	f.t.log.Info(fmt.Sprintf("💥 Disrupting connectivity to the INB hosted on %s", f.target))
	err := f.iptables(ctx, targetAgent, "-A")
	if err != nil {
		f.fail(features.IPFamilyAny, "node %s: %v", f.target, err)
		return
	}

	var cleanup = func(ctx context.Context) error {
		f.t.log.Info(fmt.Sprintf("🩹 Restoring connectivity to the INB hosted on %s", f.target))
		err := f.iptables(ctx, targetAgent, "-D")
		if err != nil {
			f.fail(features.IPFamilyAny, "node %s: %v", f.target, err)
		}

		return err
	}

	defer func() {
		if cleanup != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			cleanup(ctx)
			cancel()
		}
	}()

	f.t.log.Info("🧐 Validating that INBs status converges on all workload nodes")
	for _, agent := range clusterAgents {
		_, err := f.t.waitForINBs(ctx, agent, f.t.assertDegradedState(f.target, initial[NodeName(agent.NodeName())]))
		if err != nil {
			f.fail(features.IPFamilyAny, "node %s: %v", agent.NodeName(), err)
			return
		}
	}

	err = cleanup(ctx)
	if err != nil {
		return
	}
	cleanup = nil

	f.t.log.Info("🧐 Validating that INBs status converges on all workload nodes")
	for _, agent := range clusterAgents {
		_, err := f.t.waitForINBs(ctx, agent, f.t.assertSteadyState())
		if err != nil {
			f.fail(features.IPFamilyAny, "node %s: %v", agent.NodeName(), err)
			return
		}
	}
}

func (f *failover) iptables(ctx context.Context, agent check.Pod, op string) error {
	// It is expected that INBs are already configured with an iptables rule
	// to explicitly allow traffic to the API server:
	// > iptables -A INPUT -p tcp --dport 6443 -j ACCEPT

	var cmd = []string{"iptables", op, "INPUT", "-i", "eth0", "-j", "DROP"}
	f.t.log.Debug(fmt.Sprintf("ℹ️ Running %q on node %s", strings.Join(cmd, " "), agent.NodeName()))

	_, stderr, err := agent.K8sClient.ExecInPodWithStderr(ctx, agent.Pod.Namespace, agent.Pod.Name, defaults.AgentContainerName, cmd)
	if op == "-D" && strings.Contains(stderr.String(), "iptables: Bad rule (does a matching rule exist in that chain?)") {
		// Don't fail if we are attemping to remove a rule which doesn't already exist.
		err = nil
	}

	if err != nil {
		return fmt.Errorf("configuring iptables (%s): %w (%v)", op, err, stderr)
	}

	return nil
}
