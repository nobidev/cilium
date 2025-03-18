//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressmapha

import (
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestPolicyMap(t *testing.T) {
	testutils.PrivilegedTest(t)

	bpf.CheckOrMountFS("")
	assert.NoError(t, rlimit.RemoveMemlock())

	egressPolicyMap := createPolicyMapV2(hivetest.Lifecycle(t), DefaultPolicyConfig, ebpf.PinNone)

	sourceIP1 := netip.MustParseAddr("1.1.1.1")
	sourceIP2 := netip.MustParseAddr("1.1.1.2")

	destCIDR1 := netip.MustParsePrefix("2.2.1.0/24")
	destCIDR2 := netip.MustParsePrefix("2.2.2.0/24")

	egressIP1 := netip.MustParseAddr("3.3.3.1")
	egressIP2 := netip.MustParseAddr("3.3.3.2")

	gatewayIP1 := netip.MustParseAddr("4.4.4.1")
	gatewayIP2 := netip.MustParseAddr("4.4.4.2")

	ifIndex1 := uint32(1)
	ifIndex2 := uint32(2)

	// This will create 2 policies, respectively with 2 and 1 egress GWs:
	//
	// Source IP   Destination CIDR   Egress IP   Gateway
	// 1.1.1.1     2.2.1.0/24         3.3.3.1     0 => 4.4.4.1
	//                                            1 => 4.4.4.2
	// 1.1.1.2     2.2.2.0/24         3.3.3.2     0 => 4.4.4.1

	err := ApplyEgressPolicyV2(egressPolicyMap, sourceIP1, destCIDR1, egressIP1, []netip.Addr{gatewayIP1, gatewayIP2}, ifIndex1)
	assert.NoError(t, err)

	defer RemoveEgressPolicyV2(egressPolicyMap, sourceIP1, destCIDR1)

	err = ApplyEgressPolicyV2(egressPolicyMap, sourceIP2, destCIDR2, egressIP2, []netip.Addr{gatewayIP1}, ifIndex2)
	assert.NoError(t, err)

	defer RemoveEgressPolicyV2(egressPolicyMap, sourceIP2, destCIDR2)

	val, err := egressPolicyMap.Lookup(sourceIP1, destCIDR1)
	assert.NoError(t, err)

	assert.EqualValues(t, uint32(2), val.Size)
	assert.Equal(t, val.EgressIP.Addr(), egressIP1)
	assert.Equal(t, val.GatewayIPs[0].Addr(), gatewayIP1)
	assert.Equal(t, val.GatewayIPs[1].Addr(), gatewayIP2)
	assert.Equal(t, val.EgressIfindex, ifIndex1)

	val, err = egressPolicyMap.Lookup(sourceIP2, destCIDR2)
	assert.NoError(t, err)

	assert.EqualValues(t, uint32(1), val.Size)
	assert.Equal(t, val.EgressIP.Addr(), egressIP2)
	assert.Equal(t, val.GatewayIPs[0].Addr(), gatewayIP1)
	assert.Equal(t, val.EgressIfindex, ifIndex2)

	// Adding a policy with too many gateways should result in an error
	gatewayIPs := make([]netip.Addr, maxGatewayNodes+1)
	err = ApplyEgressPolicyV2(egressPolicyMap, sourceIP1, destCIDR1, egressIP1, gatewayIPs, ifIndex1)
	assert.ErrorContains(t, err, "cannot apply egress policy: too many gateways")

	// Update the first policy:
	//
	// - remove gatewayIP1 from the list of active gateways (by applying a
	//   new policy with just gatewayIP2)
	// - remove gatewayIP1 also from the list of healthy gateways
	err = ApplyEgressPolicyV2(egressPolicyMap, sourceIP1, destCIDR1, egressIP1, []netip.Addr{gatewayIP2}, ifIndex1)
	assert.NoError(t, err)

	// Update the first policy:
	//
	// - change the active gateway from gatewayIP2 -> gatewayIP1
	//-  keep gatewayIP2 in the list of healthy gateways
	err = ApplyEgressPolicyV2(egressPolicyMap, sourceIP1, destCIDR1, egressIP1, []netip.Addr{gatewayIP1}, ifIndex1)
	assert.NoError(t, err)

	// Update the first policy:
	//
	//-  Remove gatewayIP2 from the list of healthy gateways
	err = ApplyEgressPolicyV2(egressPolicyMap, sourceIP1, destCIDR1, egressIP1, []netip.Addr{gatewayIP1}, ifIndex1)
	assert.NoError(t, err)

	// Remove the second policy
	err = RemoveEgressPolicyV2(egressPolicyMap, sourceIP2, destCIDR2)
	assert.NoError(t, err)
}
