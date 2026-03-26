// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type clientEgressL7Connect struct{}

func (t clientEgressL7Connect) build(ct *check.ConnectivityTest, templates map[string]string) {
	// Test L7 HTTP CONNECT support using an egress policy on the clients.
	// This verifies that Envoy correctly forwards CONNECT requests when
	// L7 HTTP policies are active (issue #24276).
	newTest("client-egress-l7-http-connect", ct).
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithCiliumPolicy(templates["clientEgressL7HTTPConnectPolicyYAML"]).
		WithScenarios(tests.PodToPodConnect()).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Source().HasLabel("other", "client") &&
				a.Destination().Port() == 8080 {
				egress = check.ResultOK
				egress.HTTP = check.HTTP{
					Method: "CONNECT",
				}
				return egress, check.ResultNone
			}
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})
}
