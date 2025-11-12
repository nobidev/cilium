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
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/cilium-cli/utils/features"
)

type INBInfo struct {
	Interface   string
	ClusterName string
}

type VMAffinity string

var (
	SameNode  VMAffinity = "same-node"
	OtherNode VMAffinity = "other-node"
)

type VMKind string

var (
	VMKindClient VMKind = "client"
	VMKindEcho   VMKind = "echo"
	VMKindExtern VMKind = "extern"
)

type VMName string

func (n VMName) String() string {
	return string(n)
}

func ClientVM(network NetworkName) VMName {
	return VMName(fmt.Sprintf("client-%s", network))
}

func EchoVM(network NetworkName) VMName {
	return VMName(fmt.Sprintf("echo-same-node-%s", network))
}

func EchoOtherVM(network NetworkName) VMName {
	return VMName(fmt.Sprintf("echo-other-node-%s", network))
}

type NetworkName string

func (n NetworkName) String() string {
	return string(n)
}

type VM struct {
	ID      string
	Name    VMName
	NetName NetworkName

	NetIPv4 netip.Addr
	NetIPv6 netip.Addr

	NetIPv6Gateway netip.Addr // workaround for lack of RA in KubeVirt

	NetDNSServer netip.Addr

	NetMAC   string
	Affinity VMAffinity
	Kind     VMKind
}

func (vm *VM) IP(family features.IPFamily) netip.Addr {
	switch family {
	case features.IPFamilyV6:
		return vm.NetIPv6
	default:
		return vm.NetIPv4
	}
}

type Route struct {
	Destination netip.Prefix
	Gateway     netip.Addr
}

type NetworkData struct {
	Prefixes []string
	INBs     []INBInfo
	VMs      []VM
	Routes   []Route
}

var networkTopology = map[NetworkName]NetworkData{
	NetworkA: {
		Prefixes: []string{
			"192.168.250.0/24",
			"fd10:0:250::0/64",
		},
		INBs: []INBInfo{
			{
				Interface:   "ethA",
				ClusterName: "privnet-inb0",
			},
		},
		VMs: []VM{
			{
				ID:             "vm-A1",
				Name:           ClientVM(NetworkA),
				NetName:        NetworkA,
				NetIPv4:        netip.MustParseAddr("192.168.250.10"),
				NetIPv6:        netip.MustParseAddr("fd10:0:250::10"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetDNSServer:   netip.MustParseAddr("192.168.250.254"),
				NetMAC:         "f2:54:1c:1f:84:94",
				Affinity:       SameNode,
				Kind:           VMKindClient,
			},
			{
				ID:             "vm-A2",
				Name:           EchoVM(NetworkA),
				NetName:        NetworkA,
				NetIPv4:        netip.MustParseAddr("192.168.250.20"),
				NetIPv6:        netip.MustParseAddr("fd10:0:250::20"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetDNSServer:   netip.MustParseAddr("192.168.250.254"),
				NetMAC:         "de:a9:fd:7d:af:bf",
				Affinity:       SameNode,
				Kind:           VMKindEcho,
			},
			{
				ID:             "vm-A3",
				Name:           EchoOtherVM(NetworkA),
				NetName:        NetworkA,
				NetIPv4:        netip.MustParseAddr("192.168.250.21"),
				NetIPv6:        netip.MustParseAddr("fd10:0:250::21"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetDNSServer:   netip.MustParseAddr("192.168.250.254"),
				NetMAC:         "be:68:f6:fc:6a:4a",
				Affinity:       OtherNode,
				Kind:           VMKindEcho,
			},
		},
		Routes: []Route{
			{
				Destination: netip.MustParsePrefix("192.168.252.0/24"),
				Gateway:     netip.MustParseAddr("192.168.250.254"),
			},
			{
				Destination: netip.MustParsePrefix("fd10:0:252::/64"),
				Gateway:     netip.MustParseAddr("fd10:0:250::fffe"),
			},
			{
				Destination: netip.MustParsePrefix("192.168.255.0/24"),
				Gateway:     netip.MustParseAddr("192.168.250.200"),
			},
			{
				Destination: netip.MustParsePrefix("fd10:0:255::/64"),
				Gateway:     netip.MustParseAddr("fd10:0:250::200"),
			},
		},
	},
	NetworkB: {
		Prefixes: []string{
			"192.168.251.0/24",
			"fd10:0:251::/64",
		},
		INBs: []INBInfo{
			{
				Interface:   "ethB",
				ClusterName: "privnet-inb0",
			},
		},
		VMs: []VM{
			{
				ID:             "vm-B1",
				Name:           ClientVM(NetworkB),
				NetName:        NetworkB,
				NetIPv4:        netip.MustParseAddr("192.168.251.10"),
				NetIPv6:        netip.MustParseAddr("fd10:0:251::10"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetDNSServer:   netip.MustParseAddr("192.168.251.254"),
				NetMAC:         "42:f9:eb:33:4d:54",
				Affinity:       OtherNode,
				Kind:           VMKindClient,
			},
			{
				Name:           EchoOtherVM(NetworkB),
				NetName:        NetworkB,
				NetIPv4:        netip.MustParseAddr("192.168.251.22"),
				NetIPv6:        netip.MustParseAddr("fd10:0:251::22"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetDNSServer:   netip.MustParseAddr("192.168.251.254"),
				NetMAC:         "0e:13:85:69:e9:f7",
				Affinity:       OtherNode,
				Kind:           VMKindEcho,
			},
		},
	},
	NetworkC: {
		Prefixes: []string{
			"192.168.252.0/24",
			"fd10:0:252::/64",
		},
		INBs: []INBInfo{
			{
				Interface:   "ethC",
				ClusterName: "privnet-inb1",
			},
		},
		VMs: []VM{
			{
				ID:             "vm-C1",
				Name:           ClientVM(NetworkC),
				NetName:        NetworkC,
				NetIPv4:        netip.MustParseAddr("192.168.252.10"),
				NetIPv6:        netip.MustParseAddr("fd10:0:252::10"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetDNSServer:   netip.MustParseAddr("192.168.252.254"),
				NetMAC:         "52:1f:62:0a:ff:07",
				Affinity:       SameNode,
				Kind:           VMKindClient,
			},
			{
				Name:           EchoOtherVM(NetworkC),
				NetName:        NetworkC,
				NetIPv4:        netip.MustParseAddr("192.168.252.22"),
				NetIPv6:        netip.MustParseAddr("fd10:0:252::22"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetDNSServer:   netip.MustParseAddr("192.168.252.254"),
				NetMAC:         "5e:ae:22:a7:37:87",
				Affinity:       OtherNode,
				Kind:           VMKindEcho,
			},
		},
		Routes: []Route{
			{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
				Gateway:     netip.MustParseAddr("192.168.252.254"),
			},
			{
				Destination: netip.MustParsePrefix("::/0"),
				Gateway:     netip.MustParseAddr("fd10:0:252::fffe"),
			},
		},
	},
	NetworkD: {
		Prefixes: []string{
			"192.168.252.0/24",
			"fd10:0:252::/64",
		},
		INBs: []INBInfo{
			{
				Interface:   "ethD",
				ClusterName: "privnet-inb1",
			},
		},
		VMs: []VM{
			{
				Name:           ClientVM(NetworkD),
				NetName:        NetworkD,
				NetIPv4:        netip.MustParseAddr("192.168.252.10"),
				NetIPv6:        netip.MustParseAddr("fd10:0:252::10"),
				NetIPv6Gateway: netip.MustParseAddr("fe80::100"),
				NetDNSServer:   netip.MustParseAddr("192.168.252.254"),
				NetMAC:         "d2:32:c6:44:58:86",
				Affinity:       SameNode,
				Kind:           VMKindClient,
			},
		},
		Routes: []Route{
			{
				Destination: netip.MustParsePrefix("0.0.0.0/0"),
				Gateway:     netip.MustParseAddr("192.168.252.254"),
			},
			{
				Destination: netip.MustParsePrefix("::/0"),
				Gateway:     netip.MustParseAddr("fd10:0:252::fffe"),
			},
		},
	},
}

var UnknownDestinations = map[NetworkName][]VM{
	NetworkA: {
		{Name: "vm-net-c1", NetName: NetworkC, NetIPv4: netip.MustParseAddr("192.168.252.200"), NetIPv6: netip.MustParseAddr("fd10:0:252::200")},
		{Name: "vm-net-a1-bis", NetName: NetworkA, NetIPv4: netip.MustParseAddr("192.168.255.200"), NetIPv6: netip.MustParseAddr("fd10:0:255::200")},
	},
	NetworkB: {},
	NetworkC: {
		{Name: "vm-net-a1", NetName: NetworkA, NetIPv4: netip.MustParseAddr("192.168.250.200"), NetIPv6: netip.MustParseAddr("fd10:0:250::200")},
		{Name: "vm-net-c1-bis", NetName: NetworkC, NetIPv4: netip.MustParseAddr("192.168.252.210"), NetIPv6: netip.MustParseAddr("fd10:0:252::210")},
	},
	NetworkD: {
		{Name: "vm-net-d1-bis", NetName: NetworkD, NetIPv4: netip.MustParseAddr("192.168.252.210"), NetIPv6: netip.MustParseAddr("fd10:0:252::210")},
	},
}
