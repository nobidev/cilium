// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package test

import (
	"net/netip"

	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// egwManagerMock is a mock implementation of EGWIPsProvider ( EGWManager ). This is
// used to provide the egress IPs for the tests.
type egwManagerMock struct {
	signaler *signaler.BGPCPSignaler
	data     map[k8stypes.NamespacedName]mockEGWPolicy
}

type mockEGWPolicy struct {
	id        k8stypes.NamespacedName
	labels    map[string]string
	egressIPs []netip.Addr
}

func newEGWManagerMock(signaler *signaler.BGPCPSignaler) *egwManagerMock {
	return &egwManagerMock{
		signaler: signaler,
		data:     make(map[k8stypes.NamespacedName]mockEGWPolicy),
	}
}

func (e *egwManagerMock) updateMockPolicy(policy mockEGWPolicy) {
	e.data[policy.id] = policy
	e.signaler.Sig <- struct{}{}
}

func (e *egwManagerMock) AdvertisedEgressIPs(policySelector *slimv1.LabelSelector) (map[k8stypes.NamespacedName][]netip.Addr, error) {
	selector, err := slimv1.LabelSelectorAsSelector(policySelector)
	if err != nil {
		return nil, err
	}

	result := make(map[k8stypes.NamespacedName][]netip.Addr)
	for _, policy := range e.data {
		if selector.Matches(k8sLabels.Set(policy.labels)) {
			result[policy.id] = policy.egressIPs
		}
	}

	return result, nil
}
