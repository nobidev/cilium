// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package hooks

import (
	_ "embed"
	"strings"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	enterpriseCheck "github.com/cilium/cilium/cilium-cli/enterprise/hooks/connectivity/check"
	enterpriseFeatures "github.com/cilium/cilium/cilium-cli/enterprise/hooks/utils/features"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

// Ingress policy related files
var (
	//go:embed manifests/ingress-policy/client-egress-reserved-ingress-echo-same-node.yaml
	clientEgressReservedIngressEchoSameNodeYAML string

	//go:embed manifests/ingress-policy/ingress-policy-client-same-node.yaml
	ingressPolicyClientSameNodeYAML string

	//go:embed manifests/ingress-policy/ingress-policy-client-other-node.yaml
	ingressPolicyClientOtherNodeYAML string

	//go:embed manifests/ingress-policy/ingress-policy-egress-allowed-same-node.yaml
	ingressPolicyEgressAllowedSameNodeYAML string

	//go:embed manifests/ingress-policy/same-node-ingress-reserved-ingress.yaml
	sameNodeIngressReservedIngressYAML string

	//go:embed manifests/ingress-policy/all-egress-deny.yaml
	allEgressDenyYAML string

	//go:embed manifests/ingress-policy/all-ingress-deny.yaml
	allIngressDenyYAML string
)

func (ec *EnterpriseConnectivity) addIngressPolicyTests(ct *check.ConnectivityTest, templates map[string]string) error {
	newTest := func(ct *check.ConnectivityTest, name string) *enterpriseCheck.EnterpriseTest {
		return enterpriseCheck.NewEnterpriseConnectivityTest(ct).
			NewEnterpriseTest(name).
			WithFeatureRequirements(
				features.RequireEnabled(enterpriseFeatures.DedicatedEnvoyConfigPolicy),
				features.RequireEnabled(features.IngressController),
			)
	}

	newTest(ct, "pod-to-ingress-service-policy").
		WithCiliumPolicy(ingressPolicyClientSameNodeYAML).
		WithScenarios(tests.PodToIngress()).
		WithExpectations(func(a *check.Action) (egress check.Result, ingress check.Result) {
			// other node Ingress should be allowed as usual
			if strings.Contains(a.Destination().Name(), "cilium-ingress-other-node") {
				return check.ResultOK, check.ResultOK
			}

			// same node Ingress should be allowed only for name:client pod
			if a.Source().HasLabel("name", "client") &&
				strings.Contains(a.Destination().Name(), "cilium-ingress-same-node") {
				return check.ResultOK, check.ResultOK
			}

			// other traffic should be dropped
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})

	newTest(ct, "pod-to-ingress-service-policy-other-node").
		WithCiliumPolicy(ingressPolicyClientOtherNodeYAML).
		WithScenarios(tests.PodToIngress()).
		WithExpectations(func(a *check.Action) (egress check.Result, ingress check.Result) {
			// other node Ingress should be allowed as usual
			if strings.Contains(a.Destination().Name(), "cilium-ingress-same-node") {
				return check.ResultOK, check.ResultOK
			}

			// same node Ingress should be allowed only for name:client pod
			if a.Source().HasLabel("other", "client-other-node") &&
				strings.Contains(a.Destination().Name(), "cilium-ingress-other-node") {
				return check.ResultOK, check.ResultOK
			}

			// other traffic should be dropped
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})

	newTest(ct, "pod-to-ingress-service-policy-egress-same-node-allowed").
		WithCiliumPolicy(ingressPolicyEgressAllowedSameNodeYAML).
		WithScenarios(tests.PodToIngress()).
		WithExpectations(func(a *check.Action) (egress check.Result, ingress check.Result) {
			if strings.Contains(a.Destination().Name(), "cilium-ingress-same-node") {
				return check.ResultOK, check.ResultOK
			}
			// other traffic should be dropped
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})

	newTest(ct, "pod-to-ingress-service-policy-with-default-egress-deny").
		WithCiliumPolicy(allEgressDenyYAML).
		WithCiliumPolicy(clientEgressReservedIngressEchoSameNodeYAML).
		WithCiliumPolicy(ingressPolicyEgressAllowedSameNodeYAML).
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]).
		WithScenarios(tests.PodToIngress()).
		WithExpectations(func(a *check.Action) (egress check.Result, ingress check.Result) {
			// only explicit allowed traffic should be allowed
			if a.Source().HasLabel("name", "client") &&
				strings.Contains(a.Destination().Name(), "cilium-ingress-same-node") {
				return check.ResultOK, check.ResultOK
			}

			// other traffic should be dropped
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})

	newTest(ct, "pod-to-ingress-service-policy-with-default-ingress-deny").
		WithCiliumPolicy(allIngressDenyYAML).
		WithCiliumPolicy(ingressPolicyClientSameNodeYAML).
		WithCiliumPolicy(sameNodeIngressReservedIngressYAML).
		WithScenarios(tests.PodToIngress()).
		WithExpectations(func(a *check.Action) (egress check.Result, ingress check.Result) {
			// only explicit allowed traffic should be allowed
			if a.Source().HasLabel("name", "client") &&
				strings.Contains(a.Destination().Name(), "cilium-ingress-same-node") {
				return check.ResultOK, check.ResultOK
			}

			// other traffic should be dropped
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})

	newTest(ct, "pod-to-ingress-service-policy-with-default-deny").
		WithCiliumPolicy(allEgressDenyYAML).
		WithCiliumPolicy(clientEgressReservedIngressEchoSameNodeYAML).
		WithCiliumPolicy(ingressPolicyEgressAllowedSameNodeYAML).
		WithCiliumPolicy(templates["clientEgressOnlyDNSPolicyYAML"]).
		WithCiliumPolicy(allIngressDenyYAML).
		WithCiliumPolicy(ingressPolicyClientSameNodeYAML).
		WithCiliumPolicy(sameNodeIngressReservedIngressYAML).
		WithScenarios(tests.PodToIngress()).
		WithExpectations(func(a *check.Action) (egress check.Result, ingress check.Result) {
			// only explicit allowed traffic should be allowed
			if a.Source().HasLabel("name", "client") &&
				strings.Contains(a.Destination().Name(), "cilium-ingress-same-node") {
				return check.ResultOK, check.ResultOK
			}

			// other traffic should be dropped
			return check.ResultDefaultDenyEgressDrop, check.ResultNone
		})

	return nil
}
