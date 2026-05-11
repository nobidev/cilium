// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type dsrIPIPLoadbalancing struct{}

func (t dsrIPIPLoadbalancing) build(ct *check.ConnectivityTest, _ map[string]string) {
	// Exercises annotation-based DSR-IPIP: per-service DSR
	// (service.cilium.io/forwarding-mode=dsr) on a cluster with
	// loadBalancer.dsrDispatch=ipip and bpf.lbModeAnnotation=true.
	//
	// Requires:
	//   - NodeWithoutCilium: external client lives on a node not running
	//     Cilium, so traffic enters via the physical netdev and exercises
	//     bpf_host's do_netdev() IPIP decap path.
	//   - LBModeAnnotation: agent honors the per-service forwarding-mode
	//     annotation; without it, the DSR annotation is a no-op and the
	//     service would be load-balanced via the cluster default (SNAT
	//     under the lb-6 matrix variant), defeating the test.
	//   - LBDSRDispatch == "ipip": the dispatch we want to exercise here
	//     is IPIP specifically (vs Geneve or option-header).
	newTest("dsr-ipip-loadbalancing", ct).
		WithFeatureRequirements(
			features.RequireEnabled(features.NodeWithoutCilium),
			features.RequireEnabled(features.LBModeAnnotation),
			features.RequireMode(features.LBDSRDispatch, "ipip"),
		).
		WithScenarios(tests.OutsideToDSRLoadBalancer())
}
