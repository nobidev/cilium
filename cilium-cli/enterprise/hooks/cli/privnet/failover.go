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
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
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
		inbs, err := f.getINBs(ctx, agent, f.assertSteadyState())
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
		_, err := f.waitForINBs(ctx, agent, f.assertDegradedState(initial[NodeName(agent.NodeName())]))
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
		_, err := f.waitForINBs(ctx, agent, f.assertSteadyState())
		if err != nil {
			f.fail(features.IPFamilyAny, "node %s: %v", agent.NodeName(), err)
			return
		}
	}
}

type inbs struct {
	active    NodeName
	standby   []NodeName
	unhealthy []NodeName
}

type activeINBs map[NetworkName]NodeName

func (f *failover) getINBs(
	ctx context.Context, agent check.Pod, validate func(NetworkName, NodeName, inbs) error,
) (activeINBs, error) {
	stdout, err := agent.K8sClient.ExecInPod(ctx, agent.Pod.Namespace, agent.Pod.Name, defaults.AgentContainerName,
		[]string{"cilium-dbg", "shell", "--", "db/show", "privnet-inbs", "--format=yaml"},
	)

	if err != nil {
		return nil, fmt.Errorf("retrieving INBs: %w", err)
	}

	var (
		summary = make(map[NetworkName]inbs)
		active  = make(activeINBs)
	)

	for item := range bytes.SplitSeq(stdout.Bytes(), []byte("\n---")) {
		var inb tables.INB

		err = yaml.Unmarshal(item, &inb)
		if err != nil {
			return nil, fmt.Errorf("parsing INBs: %w", err)
		}

		var (
			network = NetworkName(inb.Network)
			node    = NodeName(inb.Node.Name)
			state   = summary[network]
		)

		switch inb.Role {
		case tables.INBRoleActive:
			state.active = node
			active[network] = node
		case tables.INBRoleStandby:
			state.standby = append(state.standby, node)
		case tables.INBRoleNone:
			state.unhealthy = append(state.unhealthy, node)
		}

		summary[network] = state
	}

	for network := range f.t.Networks() {
		if err := validate(network, NodeName(agent.NodeName()), summary[network]); err != nil {
			return nil, fmt.Errorf("validating INBs: %w", err)
		}
	}

	return active, nil
}

func (f *failover) waitForINBs(
	ctx context.Context, agent check.Pod, validate func(NetworkName, NodeName, inbs) error,
) (activeINBs, error) {
	ctx, cancel := context.WithTimeout(ctx, check.ShortTimeout)
	defer cancel()

	f.t.log.Info(fmt.Sprintf("⌛ Waiting for INBs to converge on node %s", agent.NodeName()))

	var lastErr error
	for {
		active, err := f.getINBs(ctx, agent, validate)
		if err == nil {
			return active, nil
		}

		lastErr = err
		f.t.log.Debug("INB check failed, retrying",
			logfields.Error, err,
			logfields.Node, agent.NodeName(),
			logfields.Interval, check.PollInterval,
		)

		select {
		case <-time.After(check.PollInterval):
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout out waiting for INBs to converge: %w", lastErr)
		}
	}
}

func (f *failover) assertSteadyState() func(NetworkName, NodeName, inbs) error {
	return func(network NetworkName, node NodeName, state inbs) error {
		switch {
		case state.active == "":
			return errors.New("no active INB")
		case len(state.standby) != f.expectedStandby(network):
			return fmt.Errorf("got %d standby INBs, %d expected", len(state.standby), f.expectedStandby(network))
		case len(state.unhealthy) != 0:
			return fmt.Errorf("got %d unhealthy INBs, 0 expected", len(state.unhealthy))

		default:
			f.t.log.Debug("INBs converged to steady state",
				logfields.Network, network,
				logfields.Node, node,
				logfields.Active, state.active,
			)
			return nil
		}
	}
}

func (f *failover) assertDegradedState(previous activeINBs) func(NetworkName, NodeName, inbs) error {
	return func(network NetworkName, node NodeName, state inbs) error {
		var (
			affected = f.target == previous[network]
			standby  = f.expectedStandby(network)
		)

		switch {
		case affected && state.active == previous[network]:
			return errors.New("active INB should have changed")
		case affected && standby == 0 && state.active != "":
			// There was no standby INBs, so we should have no active INB now.
			return errors.New("got active INB, none expected")
		case affected && standby > 0 && state.active == "":
			// There was at least one standby INB, so we should have an active INB now.
			return errors.New("no active INB")

		case !affected && state.active != previous[network]:
			return errors.New("active INB should not have changed")

		case len(state.standby) != max(standby-1, 0):
			return fmt.Errorf("got %d standby INBs, %d expected", len(state.standby), max(standby-1, 0))

		case (affected || standby > 0) && len(state.unhealthy) != 1:
			return fmt.Errorf("got %d unhealthy INBs, 1 expected", len(state.unhealthy))
		case (!affected && standby == 0) && len(state.unhealthy) != 0:
			return fmt.Errorf("got %d unhealthy INBs, 0 expected", len(state.unhealthy))

		default:
			f.t.log.Debug("INBs converged to degraded state",
				logfields.Network, network,
				logfields.Node, node,
				logfields.Active, state.active,
			)
			return nil
		}
	}
}

func (f *failover) expectedStandby(network NetworkName) int {
	// This is correct under the assumption that INB clusters have a single node.
	return max(len(networkTopology[network].INBs)-1, 0)
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
