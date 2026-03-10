// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tables

import (
	"net/netip"
	"testing"

	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestSubnetEqualsHandlesDefaultDHCP(t *testing.T) {
	a := Subnet{
		SubnetSpec: SubnetSpec{
			Network: "blue",
			Name:    "subnet-a",
			CIDRv4:  netip.MustParsePrefix("10.0.0.0/24"),
		},
	}
	b := Subnet{
		SubnetSpec: SubnetSpec{
			Network: "blue",
			Name:    "subnet-a",
			CIDRv4:  netip.MustParsePrefix("10.0.0.0/24"),
		},
	}

	if !a.Equals(b) {
		t.Fatalf("expected subnets with default DHCP to be equal")
	}
}

func TestSubnetEqualsComparesDHCPStructurally(t *testing.T) {
	a := Subnet{
		SubnetSpec: SubnetSpec{
			Network: "blue",
			Name:    "subnet-a",
			CIDRv4:  netip.MustParsePrefix("10.0.0.0/24"),
		},
		DHCP: v1alpha1.PrivateNetworkSubnetDHCPSpec{
			Mode: v1alpha1.PrivateNetworkDHCPModeRelay,
			Relay: &v1alpha1.PrivateNetworkDHCPRelaySpec{
				ServerAddress: "192.0.2.10:67",
				Option82: &v1alpha1.PrivateNetworkDHCPOption82Spec{
					CircuitID: "circuit-a",
					RemoteID:  "remote-a",
				},
			},
		},
	}
	b := Subnet{
		SubnetSpec: SubnetSpec{
			Network: "blue",
			Name:    "subnet-a",
			CIDRv4:  netip.MustParsePrefix("10.0.0.0/24"),
		},
		DHCP: v1alpha1.PrivateNetworkSubnetDHCPSpec{
			Mode: v1alpha1.PrivateNetworkDHCPModeRelay,
			Relay: &v1alpha1.PrivateNetworkDHCPRelaySpec{
				ServerAddress: "192.0.2.10:67",
				Option82: &v1alpha1.PrivateNetworkDHCPOption82Spec{
					CircuitID: "circuit-a",
					RemoteID:  "remote-a",
				},
			},
		},
	}

	if !a.Equals(b) {
		t.Fatalf("expected structurally equal DHCP config to be equal")
	}

	b.DHCP.Relay.Option82.RemoteID = "remote-b"
	if a.Equals(b) {
		t.Fatalf("expected DHCP configs with different option82 to differ")
	}
}
