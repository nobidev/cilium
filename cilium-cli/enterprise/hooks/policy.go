//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package hooks

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

//go:embed manifests/client-ingress-to-echo-ordered-ns.yaml
var clientIngressToEchoOrderedNS string

//go:embed manifests/client-ingress-to-echo-ordered-wildcard.yaml
var clientIngressToEchoOrderedWildcard string

//go:embed manifests/client-ingress-to-echo-ordered-portrange.yaml
var clientIngressToEchoOrderedPortrange string

var (
	clientLabel  = map[string]string{"name": "client"}
	client2Label = map[string]string{"name": "client2"}
)

// orderedPolicyVersion is the version ranges that support ordered policy.
// This is <1.19 because main-ce does not support ordered policy
const orderedPolicyVersion = ">=1.17.0 < 1.19.0"

func (ec *EnterpriseConnectivity) addOrderedPolicyTests(ct *check.ConnectivityTest, templates map[string]string) error {
	test := check.NewTest("ordered-policy-ns", ct.Params().Verbose, ct.Params().Debug)
	ct.AddTest(test).
		WithResources(templates["clientIngressToEchoOrderedNS"]).
		WithCiliumVersion(orderedPolicyVersion).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(clientLabel)),  // Client to echo should be allowed
			tests.PodToPod(tests.WithSourceLabelsOption(client2Label)), // Client2 to echo should be denied
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") && a.Source().HasLabel("name", "client2") {
				return check.ResultDropCurlTimeout, check.ResultPolicyDenyIngressDrop
			}
			return check.ResultOK, check.ResultOK
		})

	test2 := check.NewTest("ordered-policy-wildcard", ct.Params().Verbose, ct.Params().Debug)
	ct.AddTest(test2).
		WithResources(templates["clientIngressToEchoOrderedWildcard"]).
		WithCiliumVersion(orderedPolicyVersion).
		WithScenarios(
			tests.PodToPod(tests.WithSourceLabelsOption(clientLabel)),  // Client to echo should be allowed
			tests.PodToPod(tests.WithSourceLabelsOption(client2Label)), // Client2 to echo should be denied
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Destination().HasLabel("kind", "echo") && a.Source().HasLabel("name", "client2") {
				return check.ResultDropCurlTimeout, check.ResultPolicyDenyIngressDrop
			}
			return check.ResultOK, check.ResultOK
		})

		// Disabled until https://github.com/cilium/cilium/issues/38840 is resolved.
		// This test triggers a latent proxylib bug -- not an ordered policy bug.
		/*
			test3 := check.NewTest("ordered-policy-portrange", ct.Params().Verbose, ct.Params().Debug)
			ct.AddTest(test3).
				WithResources(templates["clientIngressToEchoOrderedPortrange"]).
				WithCiliumVersion(">=1.17.0 < 1.18.0"). // TODO: update this when versions change
				WithScenarios(
					tests.PodToPod(tests.WithSourceLabelsOption(clientLabel)),  // Client to echo should be allowed
					tests.PodToPod(tests.WithSourceLabelsOption(client2Label)), // Client2 to echo should be denied
				).
				WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
					if a.Destination().HasLabel("kind", "echo") && a.Source().HasLabel("name", "client2") {
						return check.ResultDropCurlTimeout, check.ResultPolicyDenyIngressDrop
					}
					return check.ResultOK, check.ResultOK
				})
		*/

	return nil
}
