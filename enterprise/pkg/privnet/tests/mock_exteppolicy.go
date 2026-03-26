//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/pkg/maps/extepspolicy"
	"github.com/cilium/cilium/pkg/maps/policymap"
)

func mockExtEPPolicyCell(t testing.TB) cell.Cell {
	t.Helper()

	return cell.Group(
		cell.Provide(
			func() extepspolicy.Writer {
				return &mockExtEpsPolicyWriter{}
			},
		),
	)
}

type mockExtEpsPolicyWriter struct{}

// Upsert registers a policy map for the given IP address.
func (m *mockExtEpsPolicyWriter) Upsert(ip netip.Addr, pm *policymap.PolicyMap) error {
	return nil
}

// Delete unregisters the policy map associated with the given IP address.
func (m *mockExtEpsPolicyWriter) Delete(ip netip.Addr) error {
	return nil
}

// MarkInitialized must be called when the initial set of entries has been written.
func (m *mockExtEpsPolicyWriter) MarkInitialized() {}
