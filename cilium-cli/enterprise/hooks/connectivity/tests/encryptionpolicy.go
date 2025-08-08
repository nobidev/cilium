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
	"context"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/sniff"
	enterpriseSniff "github.com/cilium/cilium/cilium-cli/enterprise/hooks/connectivity/sniff"
	enterpriseFeatures "github.com/cilium/cilium/cilium-cli/enterprise/hooks/utils/features"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

// PodToPodEncryptionPolicy is a test case which checks the following:
//   - Traffic between pods on different nodes that is selected by an encryption
//     policy can be observed on the cilium_wg0 net device, and is thus encrypted.
//   - Traffic between pods on different nodes that is not selected by an encryption
//     policy, is not observed on the cilium_wg0 net device, and is thus not encrypted.
//
// The checks are implemented by curl'ing a server pod from a client pod, and
// then inspecting tcpdump captures from the client and server pod's nodes.
func PodToPodEncryptionPolicy() check.Scenario {
	return &podToPodEncryptionPolicy{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type podToPodEncryptionPolicy struct {
	check.ScenarioBase
}

func (s *podToPodEncryptionPolicy) Name() string {
	return "pod-to-pod-encryption-policy"
}

func (s *podToPodEncryptionPolicy) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	var client1 check.Pod
	for _, pod := range ct.ClientPods() {
		if pod.Labels()["name"] == "client" {
			client1 = pod
			break
		}
	}
	if client1.Pod == nil {
		t.Fatal("could not find a matching first client pod")
	}

	var client2 check.Pod
	for _, pod := range ct.ClientPods() {
		if pod.Labels()["name"] == "client2" && pod.Pod.Status.HostIP == client1.Pod.Status.HostIP {
			client2 = pod
			break
		}
	}
	if client2.Pod == nil {
		t.Fatal("could not find a matching second client pod")
	}

	clustermesh := ct.Params().MultiCluster != ""

	var echo check.Pod
	for _, pod := range ct.EchoPods() {
		// if we run this test against a clustermesh, ensure echo is in a different cluster than the clients
		if clustermesh && pod.K8sClient.ClusterName() != client1.K8sClient.ClusterName() {
			echo = pod
			break
		}

		// if we run against a single cluster, ensure echo is on another node than the clients
		if !clustermesh && pod.Pod.Status.HostIP != client1.Pod.Status.HostIP {
			echo = pod
			break
		}
	}
	if echo.Pod == nil {
		t.Fatal("could not find a matching echo pod")
	}

	// client1Host is a pod running on the same node as the client pod, just in the host netns.
	client1Host := ct.HostNetNSPodsByNode()[client1.Pod.Spec.NodeName]
	// client2Host is a pod running on the same node as the client pod, just in the host netns.
	client2Host := ct.HostNetNSPodsByNode()[client2.Pod.Spec.NodeName]
	// echoHost is a pod running in a remote node's host netns.
	echoHost := ct.HostNetNSPodsByNode()[echo.Pod.Spec.NodeName]

	// check if between pods were an encryption policy is applied the traffic is redirected to the
	// wireguard device
	t.ForEachIPFamily(func(ipFam features.IPFamily) {
		testPolicyApplied(ctx, t, s, &client1, &echo, &client1Host, &echoHost, ipFam, true)
	})

	// check if between pods were no encryption policy is applied the traffic is not redirected to the
	// wireguard device
	t.ForEachIPFamily(func(ipFam features.IPFamily) {
		testPolicyApplied(ctx, t, s, &client2, &echo, &client2Host, &echoHost, ipFam, false)
	})

}

func testPolicyApplied(ctx context.Context, t *check.Test, s check.Scenario,
	client, server, clientHost, serverHost *check.Pod,
	ipFam features.IPFamily, packetsExpected bool,
) {
	var finalizers []func() error

	// on exit, run registered finalizers
	defer func() {
		for _, f := range finalizers {
			if err := f(); err != nil {
				t.Infof("Failed to run finalizer: %w", err)
			}
		}
	}()

	iface := "cilium_wg0"
	srcFilter := getFilter(ctx, t, client, server, ipFam)

	snifferMode := sniff.ModeAssert
	if packetsExpected {
		snifferMode = sniff.ModeSanity
	}

	srcSniffer, cancel, err := sniff.Sniff(ctx, s.Name(), clientHost, iface, srcFilter, snifferMode, sniff.SniffKillTimeout, t)
	if err != nil {
		t.Fatal(err)
	}
	finalizers = append(finalizers, cancel)

	var dstSniffer *sniff.Sniffer
	dstFilter := getFilter(ctx, t, server, client, ipFam)

	dstSniffer, cancel, err = sniff.Sniff(ctx, s.Name(), serverHost, iface, dstFilter, snifferMode, sniff.SniffKillTimeout, t)
	if err != nil {
		t.Fatal(err)
	}
	finalizers = append(finalizers, cancel)

	// Curl the server from the client to generate some traffic
	t.NewAction(s, fmt.Sprintf("curl-%s", ipFam), client, server, ipFam).Run(func(a *check.Action) {
		a.ExecInPod(ctx, t.Context().CurlCommand(server, ipFam, true, nil))
		srcSniffer.Validate(a)
		dstSniffer.Validate(a)
	})
}

func getFilter(ctx context.Context, t *check.Test, client *check.Pod, server *check.Pod, ipFam features.IPFamily) string {
	tunnelEnabled := false
	localTunnel, _ := t.Context().Feature(features.Tunnel)
	if localTunnel.Enabled {
		tunnelEnabled = true
	}

	if t.Context().Params().MultiCluster != "" {
		remoteTunnel, _ := t.Context().Feature(enterpriseFeatures.RemoteClusterTunnel)
		fallback, _ := t.Context().Feature(enterpriseFeatures.FallbackRoutingMode)

		tunnelEnabled = (localTunnel.Enabled && remoteTunnel.Enabled) || ((localTunnel.Enabled || remoteTunnel.Enabled) && fallback.Mode == "tunnel")
	}

	if tunnelEnabled {
		clientHexIP, err := ipToHex(client.Address(ipFam))
		if err != nil {
			t.Fatalf("Failed to get client IP in hex notation: %s", err)
		}

		serverHexIP, err := ipToHex(server.Address(ipFam))
		if err != nil {
			t.Fatalf("Failed to get server IP in hex notation: %s", err)
		}

		tunnelFilter, err := enterpriseSniff.GetTunnelFilter(t.Context())
		if err != nil {
			t.Fatalf("Failed to build tunnel filter: %w", err)
		}

		// This filter captures VXLAN encapsulated traffic, where the inner source
		// IP matches the client pod IP and the inner destination IP matches the
		// server pod IP, for ipv4 and ipv6 respectively.
		// Encryption policies only work with VXLAN for now, no support for Geneve
		// in tests necessary. However it shouldn't be hard to add, just will require
		// slightly different offsets.
		var filter string

		if ipFam == features.IPFamilyV4 {
			if len(clientHexIP) != 8 || len(serverHexIP) != 8 {
				t.Fatalf("Hex representation of ipv4 IPs has wrong length: len(client)=%d, len(server)=%d", len(clientHexIP), len(serverHexIP))
			}
			// This filter accesses inner packet data through offsets from the outer udp header.
			// The offsets are calculated as such:
			// inner src IPv4 = udp(8) + vxlan(8) + eth(14) + ipv4 src IP(12) = 42
			// inner dst IPv4 = udp(8) + vxlan(8) + eth(14) + ipv4 dst IP(16) = 46
			// of these offsets we read 4 bytes for the respective ipv4 address
			filter = fmt.Sprintf("%s and (udp[42:4]=0x%s and udp[46:4]=0x%s)",
				tunnelFilter, clientHexIP, serverHexIP)
		}

		if ipFam == features.IPFamilyV6 {
			if len(clientHexIP) != 32 || len(serverHexIP) != 32 {
				t.Fatalf("Hex representation of ipv6 IPs has wrong length: len(client)=%d, len(server)=%d", len(clientHexIP), len(serverHexIP))
			}

			// This filter accesses inner packet data through offsets from the outer udp header.
			// The offsets are calculated as such:
			// inner src IPv6 = udp(8) + vxlan(8) + eth(14) + ipv4 src IP(8) = 38
			// inner dst IPv6 = udp(8) + vxlan(8) + eth(14) + ipv6 dst IP(24) = 54
			// Caveat for ipv6 addresses: tcpdump only allows to read 4 bytes from a given
			// offset at once. Getting a bit gnarly...
			srcIPFilter := fmt.Sprintf("(udp[38:4]=0x%s and udp[42:4]=0x%s and udp[46:4]=0x%s and udp[50:4]=0x%s)",
				clientHexIP[0:8], clientHexIP[8:16], clientHexIP[16:24], clientHexIP[24:])
			dstIPFilter := fmt.Sprintf("(udp[54:4]=0x%s and udp[58:4]=0x%s and udp[62:4]=0x%s and udp[66:4]=0x%s)",
				serverHexIP[0:8], serverHexIP[8:16], serverHexIP[16:24], serverHexIP[24:])
			filter = fmt.Sprintf("%s and %s and %s",
				tunnelFilter, srcIPFilter, dstIPFilter)
		}

		return filter
	}

	// This filter captures native traffic, where the source IP matches the client pod IP
	// and the destination IP matches the server pod IP.
	filter := fmt.Sprintf("src host %s and dst host %s", client.Address(ipFam), server.Address(ipFam))
	return filter
}

// ipToHex converts and IP address string (e.g. 10.0.0.1) to its string representation
// in hex format (e.g. 0x0a000001)
func ipToHex(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %s", ipStr)
	}

	var ipBytes []byte
	if ip.To4() != nil {
		ipBytes = ip.To4()
	} else if ip.To16() != nil {
		ipBytes = ip.To16()
	} else {
		return "", fmt.Errorf("invalid IP address: %s", ipStr)
	}

	return hex.EncodeToString(ipBytes), nil
}
