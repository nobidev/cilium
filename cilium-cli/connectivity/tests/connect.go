// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

// PodToPodConnect generates an HTTP CONNECT request from each client pod
// to each echo (server) pod in the test context. This validates that
// Envoy correctly forwards CONNECT requests when L7 HTTP policies are active,
// rather than rejecting them with 400/404 errors.
func PodToPodConnect() check.Scenario {
	return &podToPodConnect{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type podToPodConnect struct {
	check.ScenarioBase
}

func (s *podToPodConnect) Name() string {
	return "pod-to-pod-connect"
}

func (s *podToPodConnect) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, client := range ct.ClientPods() {
		if !client.HasLabel("other", "client") {
			continue
		}
		for _, echo := range ct.EchoPods() {
			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				t.NewAction(s, fmt.Sprintf("curl-%s-%d", ipFam, i), &client, echo, ipFam).Run(func(a *check.Action) {
					a.ExecInPod(ctx, a.CurlCommand(echo, "-X", "CONNECT"))

					a.ValidateFlows(ctx, client, a.GetEgressRequirements(check.FlowParameters{}))
					a.ValidateFlows(ctx, echo, a.GetIngressRequirements(check.FlowParameters{}))
				})
			})

			i++
		}
	}
}
