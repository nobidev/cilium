// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package parser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/google/uuid"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/enterprise/pkg/privnet/kvstore"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/parser"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/monitor/api"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/cilium/statedb"
)

// TestL34_NonPrivnet tests that non Privnet packets are still parsed correctly
func TestL34_NonPrivnet(t *testing.T) {
	parser := newTestParser(t)
	parser.registerEPInfo("10.16.236.178", &testutils.FakeEndpointInfo{
		ID:           1234,
		Identity:     5678,
		PodName:      "pod-10.16.236.178",
		PodNamespace: "default",
		Pod: &slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				OwnerReferences: []slim_metav1.OwnerReference{
					{
						Kind: "ReplicaSet",
						Name: "pod",
					},
				},
			},
		},
	})
	parser.registerService("10.16.236.178", 54222, &flowpb.Service{
		Name:      "service-4321",
		Namespace: "default",
	})

	parser.registerFQDN(1234, "192.168.60.11", []string{"host-192.168.60.11"})
	parser.registerIPCacheEntry("192.168.60.11",
		&ipcache.K8sMetadata{
			Namespace: "remote",
			PodName:   "pod-192.168.60.11",
		},
		ipcache.Identity{
			ID:     1234,
			Source: source.Unspec,
		})
	parser.registerService("192.168.60.11", 6443, &flowpb.Service{
		Name:      "service-1234",
		Namespace: "remote",
	})

	f := parser.decodePerfEvent(t,
		monitor.EnterpriseTraceNotify{
			TraceNotify: monitor.TraceNotify{
				Type:       byte(monitorAPI.MessageTypeTrace),
				ObsPoint:   monitorAPI.TraceFromHost,
				Version:    monitor.TraceNotifyVersion2,
				ExtVersion: monitor.TraceNotifyExtensionV1,
				SrcLabel:   1,
				DstLabel:   5678,
				Reason:     monitor.TraceReasonCtEstablished | monitor.TraceReasonEncryptMask,
				Source:     1234,
			},
		},
		[]gopacket.SerializableLayer{
			&layers.Ethernet{
				SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
				DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
				EthernetType: layers.EthernetTypeIPv4,
			},
			&layers.IPv4{
				Protocol: layers.IPProtocolTCP,
				SrcIP:    net.IPv4(192, 168, 60, 11),
				DstIP:    net.IPv4(10, 16, 236, 178),
			},
			&layers.TCP{
				SrcPort: 6443,
				DstPort: 54222,
				ACK:     true,
			},
		}).GetFlow()
	require.NotNil(t, f)

	assert.Equal(t, []string{"host-192.168.60.11"}, f.GetSourceNames())
	assert.Equal(t, "192.168.60.11", f.GetIP().GetSource())
	assert.Empty(t, f.GetIP().GetSourceXlated())
	assert.Equal(t, flowpb.TraceReason_ESTABLISHED, f.GetTraceReason())
	assert.True(t, f.GetIP().GetEncrypted())
	assert.Equal(t, uint32(6443), f.L4.GetTCP().GetSourcePort())
	assert.Equal(t, "pod-192.168.60.11", f.GetSource().GetPodName())
	assert.Equal(t, "remote", f.GetSource().GetNamespace())
	assert.Equal(t, "service-1234", f.GetSourceService().GetName())
	assert.Equal(t, "remote", f.GetSourceService().GetNamespace())
	assert.Equal(t, uint32(1), f.GetSource().GetIdentity())

	assert.Equal(t, []string(nil), f.GetDestinationNames())
	assert.Equal(t, "10.16.236.178", f.GetIP().GetDestination())
	assert.Equal(t, uint32(54222), f.L4.GetTCP().GetDestinationPort())
	assert.Equal(t, "pod-10.16.236.178", f.GetDestination().GetPodName())
	assert.Equal(t, "default", f.GetDestination().GetNamespace())
	assert.Equal(t, "service-4321", f.GetDestinationService().GetName())
	assert.Equal(t, "default", f.GetDestinationService().GetNamespace())
	assert.Equal(t, uint32(5678), f.GetDestination().GetIdentity())

	assert.Equal(t, int32(monitorAPI.MessageTypeTrace), f.GetEventType().GetType())
	assert.Equal(t, int32(monitorAPI.TraceFromHost), f.GetEventType().GetSubType())
	assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
	assert.Equal(t, &flowpb.TCPFlags{ACK: true}, f.L4.GetTCP().GetFlags())

	assert.Equal(t, flowpb.TraceObservationPoint_FROM_HOST, f.GetTraceObservationPoint())
}

func TestL34_Privnet(t *testing.T) {
	parser := newTestParser(t)

	txn := parser.db.WriteTxn(parser.privNetEps, parser.privNetMapEntries)

	parser.registerEPInfo("10.16.236.178", &testutils.FakeEndpointInfo{
		ID:           1234,
		Identity:     5678,
		PodName:      "pod-192.168.1.11",
		PodNamespace: "default",
		Pod: &slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				OwnerReferences: []slim_metav1.OwnerReference{
					{
						Kind: "ReplicaSet",
						Name: "foo",
					},
				},
			},
		},
	})
	parser.registerPrivnetEndpoint(txn, "net-a", 100, "pod-192.168.1.11", "192.168.1.11", "10.16.236.178", "10.16.236.178")

	parser.registerEPInfo("10.16.236.179", &testutils.FakeEndpointInfo{
		ID:           2345,
		Identity:     6789,
		PodName:      "pod-192.168.1.12",
		PodNamespace: "default",
		Pod: &slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				OwnerReferences: []slim_metav1.OwnerReference{
					{
						Kind: "ReplicaSet",
						Name: "bar",
					},
				},
			},
		},
	})
	parser.registerPrivnetEndpoint(txn, "net-a", 100, "pod-192.168.1.12", "192.168.1.12", "10.16.236.179", "10.16.236.180")

	parser.registerIPCacheEntry("10.17.60.13",
		&ipcache.K8sMetadata{
			Namespace: "remote",
			PodName:   "pod-192.168.60.13",
		},
		ipcache.Identity{
			ID:     7890,
			Source: source.Unspec,
		})
	parser.registerPrivnetEndpoint(txn, "net-a", 100, "pod-192.168.60.13", "192.168.60.13", "10.17.60.13")

	txn.Commit()

	t.Run("pod-to-local-pod", func(t *testing.T) {
		t.Run("trace to_lxc", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseTraceNotify{
					TraceNotify: monitor.TraceNotify{
						Type:       byte(monitorAPI.MessageTypeTrace),
						ObsPoint:   monitorAPI.TraceToLxc,
						Version:    monitor.TraceNotifyVersion2,
						ExtVersion: monitor.TraceNotifyExtensionV1,
						SrcLabel:   5678,
						DstLabel:   6789,
						Reason:     monitor.TraceReasonCtEstablished,
						Source:     1234,
					},
					SrcNetID: 100,
					DstNetID: 100,
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{6, 7, 8, 9, 1, 2},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						SrcIP:    net.IPv4(192, 168, 1, 11),
						DstIP:    net.IPv4(192, 168, 1, 12),
					},
					&layers.TCP{
						SrcPort: 55115,
						DstPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, "192.168.1.11", f.GetIP().GetSource())
			assert.Equal(t, flowpb.TraceReason_ESTABLISHED, f.GetTraceReason())
			assert.Equal(t, uint32(55115), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, "pod-192.168.1.11", f.GetSource().GetPodName())
			assert.Equal(t, "default", f.GetSource().GetNamespace())
			assert.Equal(t, uint32(5678), f.GetSource().GetIdentity())

			assert.Equal(t, "192.168.1.12", f.GetIP().GetDestination())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, "pod-192.168.1.12", f.GetDestination().GetPodName())
			assert.Equal(t, "default", f.GetDestination().GetNamespace())
			assert.Equal(t, uint32(6789), f.GetDestination().GetIdentity())
		})

		t.Run("policy to_lxc", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterprisePolicyVerdictNotify{
					PolicyVerdictNotify: monitor.PolicyVerdictNotify{
						Type:        byte(monitorAPI.MessageTypePolicyVerdict),
						Source:      1234,
						ExtVersion:  monitor.PolicyVerdictNotifyExtensionV1,
						RemoteLabel: 6789,
						Verdict:     0,
						DstPort:     80,
					},
					SrcNetID: 0,
					DstNetID: 0,
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{6, 7, 8, 9, 1, 2},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						SrcIP:    net.IPv4(10, 16, 236, 178),
						DstIP:    net.IPv4(10, 16, 236, 179),
					},
					&layers.TCP{
						SrcPort: 52125,
						DstPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
			assert.Equal(t, "192.168.1.11", f.GetIP().GetSource())
			assert.Equal(t, uint32(52125), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, "pod-192.168.1.11", f.GetSource().GetPodName())
			assert.Equal(t, "default", f.GetSource().GetNamespace())
			assert.Equal(t, uint32(5678), f.GetSource().GetIdentity())

			assert.Equal(t, "192.168.1.12", f.GetIP().GetDestination())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, "pod-192.168.1.12", f.GetDestination().GetPodName())
			assert.Equal(t, "default", f.GetDestination().GetNamespace())
			assert.Equal(t, uint32(6789), f.GetDestination().GetIdentity())
		})

		t.Run("drop", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseDropNotify{
					DropNotify: monitor.DropNotify{
						Type:       byte(monitorAPI.MessageTypeDrop),
						Source:     1234,
						Version:    monitor.DropNotifyVersion3,
						ExtVersion: monitor.DropNotifyExtensionV1,
					},
					SrcNetID: 0,
					DstNetID: 100,
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{6, 7, 8, 9, 1, 2},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						SrcIP:    net.IPv4(10, 16, 236, 178),
						DstIP:    net.IPv4(192, 168, 1, 12),
					},
					&layers.TCP{
						SrcPort: 52125,
						DstPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, flowpb.Verdict_DROPPED, f.GetVerdict())
			assert.Equal(t, "192.168.1.11", f.GetIP().GetSource())
			assert.Equal(t, uint32(52125), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, "pod-192.168.1.11", f.GetSource().GetPodName())
			assert.Equal(t, "default", f.GetSource().GetNamespace())
			assert.Equal(t, uint32(5678), f.GetSource().GetIdentity())

			assert.Equal(t, "192.168.1.12", f.GetIP().GetDestination())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, "pod-192.168.1.12", f.GetDestination().GetPodName())
			assert.Equal(t, "default", f.GetDestination().GetNamespace())
			assert.Equal(t, uint32(6789), f.GetDestination().GetIdentity())
		})

		t.Run("unknown drop", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseDropNotify{
					DropNotify: monitor.DropNotify{
						Type:       byte(monitorAPI.MessageTypeDrop),
						SubType:    uint8(flowpb.DropReason_STALE_OR_UNROUTABLE_IP),
						Source:     1234,
						Version:    monitor.DropNotifyVersion3,
						ExtVersion: monitor.DropNotifyExtensionV1,
					},
					SrcNetID: uint16(tables.NetworkIDUnknown),
					DstNetID: uint16(tables.NetworkIDUnknown),
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{6, 7, 8, 9, 1, 2},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						SrcIP:    net.IPv4(10, 16, 236, 179),
						DstIP:    net.IPv4(10, 16, 236, 178),
					},
					&layers.TCP{
						SrcPort: 52125,
						DstPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, flowpb.Verdict_DROPPED, f.GetVerdict())
			assert.Equal(t, "10.16.236.179", f.GetIP().GetSource())
			assert.Equal(t, uint32(52125), f.L4.GetTCP().GetSourcePort())
			assert.Empty(t, f.GetSource().GetPodName())
			assert.Empty(t, f.GetSource().GetNamespace())
			assert.Equal(t, uint32(identity.ReservedIdentityWorldIPv4), f.GetSource().GetIdentity())

			assert.Equal(t, "10.16.236.178", f.GetIP().GetDestination())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetDestinationPort())
			assert.Empty(t, f.GetDestination().GetPodName())
			assert.Empty(t, f.GetDestination().GetNamespace())
			assert.Equal(t, uint32(identity.ReservedIdentityWorldIPv4), f.GetDestination().GetIdentity())
		})

	})

	t.Run("pod-to-other-pod", func(t *testing.T) {
		t.Run("from_lxc", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseTraceNotify{
					TraceNotify: monitor.TraceNotify{
						Type:       byte(monitorAPI.MessageTypeTrace),
						ObsPoint:   monitorAPI.TraceFromLxc,
						Version:    monitor.TraceNotifyVersion2,
						ExtVersion: monitor.TraceNotifyExtensionV1,
						SrcLabel:   5678,
						DstLabel:   7890,
						Reason:     monitor.TraceReasonCtEstablished,
						Source:     1234,
					},
					SrcNetID: 100,
					DstNetID: 100,
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{6, 7, 4, 9, 2, 3},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						SrcIP:    net.IPv4(192, 168, 1, 11),
						DstIP:    net.IPv4(192, 168, 60, 13),
					},
					&layers.TCP{
						SrcPort: 34183,
						DstPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, "192.168.1.11", f.GetIP().GetSource())
			assert.Equal(t, flowpb.TraceReason_ESTABLISHED, f.GetTraceReason())
			assert.Equal(t, uint32(34183), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, "pod-192.168.1.11", f.GetSource().GetPodName())
			assert.Equal(t, "default", f.GetSource().GetNamespace())
			assert.Equal(t, uint32(5678), f.GetSource().GetIdentity())

			assert.Equal(t, "192.168.60.13", f.GetIP().GetDestination())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, "pod-192.168.60.13", f.GetDestination().GetPodName())
			assert.Equal(t, "remote", f.GetDestination().GetNamespace())
			assert.Equal(t, uint32(7890), f.GetDestination().GetIdentity())
		})
		t.Run("to_overlay", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseTraceNotify{
					TraceNotify: monitor.TraceNotify{
						Type:       byte(monitorAPI.MessageTypeTrace),
						ObsPoint:   monitorAPI.TraceFromLxc,
						Version:    monitor.TraceNotifyVersion2,
						ExtVersion: monitor.TraceNotifyExtensionV1,
						SrcLabel:   5678,
						DstLabel:   7890,
						Reason:     monitor.TraceReasonCtEstablished,
						Source:     1234,
					},
					SrcNetID: 0,
					DstNetID: uint16(tables.NetworkIDUnknown),
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{6, 7, 4, 9, 2, 3},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						SrcIP:    net.IPv4(10, 16, 236, 178),
						DstIP:    net.IPv4(10, 17, 60, 13),
					},
					&layers.TCP{
						SrcPort: 34183,
						DstPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
			assert.Equal(t, "192.168.1.11", f.GetIP().GetSource())
			assert.Equal(t, flowpb.TraceReason_ESTABLISHED, f.GetTraceReason())
			assert.Equal(t, uint32(34183), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, "pod-192.168.1.11", f.GetSource().GetPodName())
			assert.Equal(t, "default", f.GetSource().GetNamespace())
			assert.Equal(t, uint32(5678), f.GetSource().GetIdentity())

			assert.Equal(t, "192.168.60.13", f.GetIP().GetDestination())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, "pod-192.168.60.13", f.GetDestination().GetPodName())
			assert.Equal(t, "remote", f.GetDestination().GetNamespace())
			assert.Equal(t, uint32(7890), f.GetDestination().GetIdentity())
		})
		t.Run("from_network", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseTraceNotify{
					TraceNotify: monitor.TraceNotify{
						Type:       byte(monitorAPI.MessageTypeTrace),
						ObsPoint:   monitorAPI.TraceFromNetwork,
						Version:    monitor.TraceNotifyVersion2,
						ExtVersion: monitor.TraceNotifyExtensionV1,
						Reason:     monitor.TraceReasonCtEstablished,
						Flags:      monitor.TraceNotifyFlagIsVXLAN,
					},
					SrcNetID: uint16(tables.NetworkIDUnknown),
					DstNetID: 0,
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{5, 7, 3, 4, 1, 3},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolUDP,
						SrcIP:    net.IPv4(10, 1, 1, 13),
						DstIP:    net.IPv4(10, 1, 1, 11),
					},
					&layers.UDP{
						SrcPort: 34183,
						DstPort: 8472,
					},
					&layers.VXLAN{
						VNI: 5678,
					},
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{6, 7, 4, 9, 2, 3},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						DstIP:    net.IPv4(10, 16, 236, 178),
						SrcIP:    net.IPv4(10, 17, 60, 13),
					},
					&layers.TCP{
						SrcPort: 34183,
						DstPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
			assert.Equal(t, flowpb.TraceReason_ESTABLISHED, f.GetTraceReason())

			assert.Equal(t, "192.168.1.11", f.GetIP().GetDestination())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, "pod-192.168.1.11", f.GetDestination().GetPodName())
			assert.Equal(t, "default", f.GetDestination().GetNamespace())
			assert.Equal(t, uint32(5678), f.GetDestination().GetIdentity())

			assert.Equal(t, "192.168.60.13", f.GetIP().GetSource())
			assert.Equal(t, uint32(34183), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, "pod-192.168.60.13", f.GetSource().GetPodName())
			assert.Equal(t, "remote", f.GetSource().GetNamespace())
			assert.Equal(t, uint32(7890), f.GetSource().GetIdentity())
		})
		t.Run("from_overlay", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseTraceNotify{
					TraceNotify: monitor.TraceNotify{
						Type:       byte(monitorAPI.MessageTypeTrace),
						ObsPoint:   monitorAPI.TraceFromLxc,
						Version:    monitor.TraceNotifyVersion2,
						ExtVersion: monitor.TraceNotifyExtensionV1,
						SrcLabel:   7890,
						DstLabel:   5678,
						Reason:     monitor.TraceReasonCtEstablished,
						Source:     1234,
					},
					SrcNetID: uint16(tables.NetworkIDUnknown),
					DstNetID: 0,
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{6, 7, 4, 9, 2, 3},
						DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						SrcIP:    net.IPv4(10, 17, 60, 13),
						DstIP:    net.IPv4(10, 16, 236, 178),
					},
					&layers.TCP{
						SrcPort: 34183,
						DstPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
			assert.Equal(t, flowpb.TraceReason_ESTABLISHED, f.GetTraceReason())

			assert.Equal(t, "192.168.1.11", f.GetIP().GetDestination())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, "pod-192.168.1.11", f.GetDestination().GetPodName())
			assert.Equal(t, "default", f.GetDestination().GetNamespace())
			assert.Equal(t, uint32(5678), f.GetDestination().GetIdentity())

			assert.Equal(t, "192.168.60.13", f.GetIP().GetSource())
			assert.Equal(t, uint32(34183), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, "pod-192.168.60.13", f.GetSource().GetPodName())
			assert.Equal(t, "remote", f.GetSource().GetNamespace())
			assert.Equal(t, uint32(7890), f.GetSource().GetIdentity())
		})
	})
	t.Run("pod-to-unknown", func(t *testing.T) {
		t.Run("trace to_lxc", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseTraceNotify{
					TraceNotify: monitor.TraceNotify{
						Type:       byte(monitorAPI.MessageTypeTrace),
						ObsPoint:   monitorAPI.TraceToLxc,
						Version:    monitor.TraceNotifyVersion2,
						ExtVersion: monitor.TraceNotifyExtensionV1,
						SrcLabel:   5678,
						Reason:     monitor.TraceReasonCtEstablished,
						Source:     1234,
					},
					SrcNetID: 100,
					DstNetID: 100,
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{6, 7, 8, 9, 1, 2},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						SrcIP:    net.IPv4(192, 168, 1, 11),
						DstIP:    net.IPv4(1, 2, 3, 4),
					},
					&layers.TCP{
						SrcPort: 55115,
						DstPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, "192.168.1.11", f.GetIP().GetSource())
			assert.Equal(t, flowpb.TraceReason_ESTABLISHED, f.GetTraceReason())
			assert.Equal(t, uint32(55115), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, "pod-192.168.1.11", f.GetSource().GetPodName())
			assert.Equal(t, "default", f.GetSource().GetNamespace())
			assert.Equal(t, uint32(5678), f.GetSource().GetIdentity())

			assert.Equal(t, "1.2.3.4", f.GetIP().GetDestination())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, identity.ReservedIdentityWorldIPv4.Uint32(), f.GetDestination().GetIdentity())
		})
		t.Run("trace from_lxc pip overlap", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseTraceNotify{
					TraceNotify: monitor.TraceNotify{
						Type:       byte(monitorAPI.MessageTypeTrace),
						ObsPoint:   monitorAPI.TraceFromLxc,
						Version:    monitor.TraceNotifyVersion2,
						ExtVersion: monitor.TraceNotifyExtensionV1,
						SrcLabel:   5678,
						Reason:     monitor.TraceReasonCtEstablished,
						Source:     1234,
					},
					SrcNetID: 100,
					DstNetID: 100,
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{6, 7, 8, 9, 1, 2},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						SrcIP:    net.IPv4(192, 168, 1, 11),
						DstIP:    net.IPv4(10, 17, 60, 13),
					},
					&layers.TCP{
						SrcPort: 55115,
						DstPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, "192.168.1.11", f.GetIP().GetSource())
			assert.Equal(t, flowpb.TraceReason_ESTABLISHED, f.GetTraceReason())
			assert.Equal(t, uint32(55115), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, "pod-192.168.1.11", f.GetSource().GetPodName())
			assert.Equal(t, "default", f.GetSource().GetNamespace())
			assert.Equal(t, uint32(5678), f.GetSource().GetIdentity())

			assert.Equal(t, "10.17.60.13", f.GetIP().GetDestination())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, identity.ReservedIdentityWorldIPv4.Uint32(), f.GetDestination().GetIdentity())
		})
		t.Run("trace to_overlay", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseTraceNotify{
					TraceNotify: monitor.TraceNotify{
						Type:       byte(monitorAPI.MessageTypeTrace),
						ObsPoint:   monitorAPI.TraceToOverlay,
						Version:    monitor.TraceNotifyVersion2,
						ExtVersion: monitor.TraceNotifyExtensionV1,
						SrcLabel:   identity.ReservedPrivnetUnknownFlow,
						Reason:     monitor.TraceReasonCtEstablished,
						Source:     1234,
					},
					SrcNetID: 0,
					DstNetID: uint16(tables.NetworkIDUnknown),
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{6, 7, 4, 9, 2, 3},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						SrcIP:    net.IPv4(10, 16, 236, 178),
						DstIP:    net.IPv4(10, 17, 60, 13),
					},
					&layers.TCP{
						SrcPort: 34183,
						DstPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
			assert.Equal(t, "192.168.1.11", f.GetIP().GetSource())
			assert.Equal(t, flowpb.TraceReason_ESTABLISHED, f.GetTraceReason())
			assert.Equal(t, uint32(34183), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, "pod-192.168.1.11", f.GetSource().GetPodName())
			assert.Equal(t, "default", f.GetSource().GetNamespace())
			assert.Equal(t, uint32(5678), f.GetSource().GetIdentity())

			assert.Equal(t, "10.17.60.13", f.GetIP().GetDestination())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, identity.ReservedIdentityWorldIPv4.Uint32(), f.GetDestination().GetIdentity())
		})
		t.Run("trace to_network", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseTraceNotify{
					TraceNotify: monitor.TraceNotify{
						Type:       byte(monitorAPI.MessageTypeTrace),
						ObsPoint:   monitorAPI.TraceToNetwork,
						Version:    monitor.TraceNotifyVersion2,
						ExtVersion: monitor.TraceNotifyExtensionV1,
						Reason:     monitor.TraceReasonCtEstablished,
						Flags:      monitor.TraceNotifyFlagIsVXLAN,
					},
					SrcNetID: 0,
					DstNetID: uint16(tables.NetworkIDUnknown),
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{5, 7, 3, 4, 1, 3},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolUDP,
						SrcIP:    net.IPv4(10, 1, 1, 13),
						DstIP:    net.IPv4(10, 1, 1, 11),
					},
					&layers.UDP{
						SrcPort: 34183,
						DstPort: 8472,
					},
					&layers.VXLAN{
						VNI: 99,
					},
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{6, 7, 4, 9, 2, 3},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						SrcIP:    net.IPv4(10, 16, 236, 178),
						DstIP:    net.IPv4(10, 17, 60, 13),
					},
					&layers.TCP{
						SrcPort: 34183,
						DstPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
			assert.Equal(t, "192.168.1.11", f.GetIP().GetSource())
			assert.Equal(t, flowpb.TraceReason_ESTABLISHED, f.GetTraceReason())
			assert.Equal(t, uint32(34183), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, "pod-192.168.1.11", f.GetSource().GetPodName())
			assert.Equal(t, "default", f.GetSource().GetNamespace())
			assert.Equal(t, uint32(5678), f.GetSource().GetIdentity())

			assert.Equal(t, "10.17.60.13", f.GetIP().GetDestination())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, identity.ReservedIdentityWorldIPv4.Uint32(), f.GetDestination().GetIdentity())
		})
		t.Run("trace from_network", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseTraceNotify{
					TraceNotify: monitor.TraceNotify{
						Type:       byte(monitorAPI.MessageTypeTrace),
						ObsPoint:   monitorAPI.TraceFromNetwork,
						Version:    monitor.TraceNotifyVersion2,
						ExtVersion: monitor.TraceNotifyExtensionV1,
						Reason:     monitor.TraceReasonCtReply,
						Flags:      monitor.TraceNotifyFlagIsVXLAN,
					},
					SrcNetID: uint16(tables.NetworkIDUnknown),
					DstNetID: 0,
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{5, 7, 3, 4, 1, 3},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolUDP,
						SrcIP:    net.IPv4(10, 1, 1, 11),
						DstIP:    net.IPv4(10, 1, 1, 13),
					},
					&layers.UDP{
						SrcPort: 34183,
						DstPort: 8472,
					},
					&layers.VXLAN{
						VNI: 99,
					},
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{6, 7, 4, 9, 2, 3},
						DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						DstIP:    net.IPv4(10, 16, 236, 178),
						SrcIP:    net.IPv4(10, 17, 60, 13),
					},
					&layers.TCP{
						SrcPort: 80,
						DstPort: 34183,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
			assert.Equal(t, flowpb.TraceReason_REPLY, f.GetTraceReason())

			assert.Equal(t, "192.168.1.11", f.GetIP().GetDestination())
			assert.Equal(t, uint32(34183), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, "pod-192.168.1.11", f.GetDestination().GetPodName())
			assert.Equal(t, "default", f.GetDestination().GetNamespace())
			assert.Equal(t, uint32(5678), f.GetDestination().GetIdentity())

			assert.Equal(t, "10.17.60.13", f.GetIP().GetSource())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, identity.ReservedIdentityWorldIPv4.Uint32(), f.GetSource().GetIdentity())
		})
		t.Run("trace from_overlay", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseTraceNotify{
					TraceNotify: monitor.TraceNotify{
						Type:       byte(monitorAPI.MessageTypeTrace),
						ObsPoint:   monitorAPI.TraceFromOverlay,
						Version:    monitor.TraceNotifyVersion2,
						ExtVersion: monitor.TraceNotifyExtensionV1,
						Reason:     monitor.TraceReasonCtReply,
						SrcLabel:   identity.ReservedPrivnetUnknownFlow,
					},
					SrcNetID: uint16(tables.NetworkIDUnknown),
					DstNetID: 0,
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{6, 7, 4, 9, 2, 3},
						DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						DstIP:    net.IPv4(10, 16, 236, 178),
						SrcIP:    net.IPv4(10, 17, 60, 13),
					},
					&layers.TCP{
						SrcPort: 80,
						DstPort: 34183,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
			assert.Equal(t, flowpb.TraceReason_REPLY, f.GetTraceReason())

			assert.Equal(t, "192.168.1.11", f.GetIP().GetDestination())
			assert.Equal(t, uint32(34183), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, "pod-192.168.1.11", f.GetDestination().GetPodName())
			assert.Equal(t, "default", f.GetDestination().GetNamespace())
			assert.Equal(t, uint32(5678), f.GetDestination().GetIdentity())

			assert.Equal(t, "10.17.60.13", f.GetIP().GetSource())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, identity.ReservedIdentityWorldIPv4.Uint32(), f.GetSource().GetIdentity())
		})
		t.Run("drop", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseDropNotify{
					DropNotify: monitor.DropNotify{
						Type:       byte(monitorAPI.MessageTypeDrop),
						Source:     1234,
						Version:    monitor.DropNotifyVersion3,
						ExtVersion: monitor.DropNotifyExtensionV1,
						Flags:      monitor.TraceNotifyFlagIsVXLAN,
					},
					DstNetID: uint16(tables.NetworkIDUnknown),
					SrcNetID: 0,
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{5, 7, 3, 4, 1, 3},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolUDP,
						SrcIP:    net.IPv4(10, 1, 1, 13),
						DstIP:    net.IPv4(10, 1, 1, 11),
					},
					&layers.UDP{
						SrcPort: 34183,
						DstPort: 8472,
					},
					&layers.VXLAN{
						VNI: 99,
					},
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{6, 7, 4, 9, 2, 3},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						SrcIP:    net.IPv4(10, 16, 236, 178),
						DstIP:    net.IPv4(10, 17, 60, 13),
					},
					&layers.TCP{
						SrcPort: 34183,
						DstPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, flowpb.Verdict_DROPPED, f.GetVerdict())
			assert.Equal(t, "192.168.1.11", f.GetIP().GetSource())
			assert.Equal(t, uint32(34183), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, "pod-192.168.1.11", f.GetSource().GetPodName())
			assert.Equal(t, "default", f.GetSource().GetNamespace())
			assert.Equal(t, uint32(5678), f.GetSource().GetIdentity())

			assert.Equal(t, "10.17.60.13", f.GetIP().GetDestination())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, identity.ReservedIdentityWorldIPv4.Uint32(), f.GetDestination().GetIdentity())
		})
	})
}

func TestL34_Privnet_INB(t *testing.T) {
	parser := newTestParser(t)

	txn := parser.db.WriteTxn(parser.privNetEps, parser.privNetMapEntries)

	parser.registerIPCacheEntry("10.17.60.13",
		&ipcache.K8sMetadata{
			Namespace: "local",
			PodName:   "extEP-192.168.60.13",
		},
		ipcache.Identity{
			ID:     7890,
			Source: source.Unspec,
		})
	parser.registerPrivnetEndpoint(txn, "net-a", 102, "extEP-192.168.60.13", "192.168.60.13", "10.17.60.13")

	parser.registerIPCacheEntry("10.17.70.14",
		&ipcache.K8sMetadata{
			Namespace: "remote",
			PodName:   "pod-192.168.60.14",
		},
		ipcache.Identity{
			ID:     1234,
			Source: source.Unspec,
		})
	parser.registerPrivnetEndpoint(txn, "net-a", 102, "pod-192.168.60.14", "192.168.60.14", "10.17.70.14")

	txn.Commit()

	t.Run("external endpoint", func(t *testing.T) {
		t.Run("trace from_network", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseTraceNotify{
					TraceNotify: monitor.TraceNotify{
						Type:       byte(monitorAPI.MessageTypeTrace),
						ObsPoint:   monitorAPI.TraceFromNetwork,
						Version:    monitor.TraceNotifyVersion2,
						ExtVersion: monitor.TraceNotifyExtensionV1,
						Reason:     monitor.TraceReasonCtEstablished,
						Flags:      monitor.TraceNotifyFlagIsVXLAN,
					},
					SrcNetID: 0,
					DstNetID: uint16(tables.NetworkIDUnknown),
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{5, 7, 3, 4, 1, 3},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolUDP,
						SrcIP:    net.IPv4(10, 1, 1, 13),
						DstIP:    net.IPv4(10, 1, 1, 11),
					},
					&layers.UDP{
						SrcPort: 34183,
						DstPort: 8472,
					},
					&layers.VXLAN{
						VNI: 7890,
					},
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{6, 7, 4, 9, 2, 3},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						DstIP:    net.IPv4(10, 17, 60, 13),
						SrcIP:    net.IPv4(10, 17, 70, 14),
					},
					&layers.TCP{
						SrcPort: 34182,
						DstPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
			assert.Equal(t, flowpb.TraceReason_ESTABLISHED, f.GetTraceReason())

			assert.Equal(t, "192.168.60.13", f.GetIP().GetDestination())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, "extEP-192.168.60.13", f.GetDestination().GetPodName())
			assert.Equal(t, "local", f.GetDestination().GetNamespace())
			assert.Equal(t, uint32(7890), f.GetDestination().GetIdentity())

			assert.Equal(t, "192.168.60.14", f.GetIP().GetSource())
			assert.Equal(t, uint32(34182), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, "pod-192.168.60.14", f.GetSource().GetPodName())
			assert.Equal(t, "remote", f.GetSource().GetNamespace())
			assert.Equal(t, uint32(1234), f.GetSource().GetIdentity())
		})
		t.Run("policy from_overlay", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterprisePolicyVerdictNotify{
					PolicyVerdictNotify: monitor.PolicyVerdictNotify{
						Type:        byte(monitorAPI.MessageTypePolicyVerdict),
						ExtVersion:  monitor.PolicyVerdictNotifyExtensionV1,
						RemoteLabel: 7890,
						Verdict:     0,
						DstPort:     80,
					},
					SrcNetID: 0,
					DstNetID: 0,
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{6, 7, 8, 9, 1, 2},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						DstIP:    net.IPv4(10, 17, 60, 13),
						SrcIP:    net.IPv4(10, 17, 70, 14),
					},
					&layers.TCP{
						SrcPort: 34182,
						DstPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
			assert.Equal(t, "192.168.60.13", f.GetIP().GetDestination())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, "extEP-192.168.60.13", f.GetDestination().GetPodName())
			assert.Equal(t, "local", f.GetDestination().GetNamespace())
			assert.Equal(t, uint32(7890), f.GetDestination().GetIdentity())

			assert.Equal(t, "192.168.60.14", f.GetIP().GetSource())
			assert.Equal(t, uint32(34182), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, "pod-192.168.60.14", f.GetSource().GetPodName())
			assert.Equal(t, "remote", f.GetSource().GetNamespace())
			assert.Equal(t, uint32(1234), f.GetSource().GetIdentity())
		})
		t.Run("trace from_network attached", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseTraceNotify{
					TraceNotify: monitor.TraceNotify{
						Type:       byte(monitorAPI.MessageTypeTrace),
						ObsPoint:   monitorAPI.TraceFromNetwork,
						Version:    monitor.TraceNotifyVersion2,
						ExtVersion: monitor.TraceNotifyExtensionV1,
						Reason:     monitor.TraceReasonCtEstablished,
					},
					SrcNetID: 102,
					DstNetID: 102,
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{6, 7, 4, 9, 2, 3},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						SrcIP:    net.IPv4(192, 168, 60, 13),
						DstIP:    net.IPv4(192, 168, 60, 14),
					},
					&layers.TCP{
						DstPort: 34182,
						SrcPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
			assert.Equal(t, flowpb.TraceReason_ESTABLISHED, f.GetTraceReason())

			assert.Equal(t, "192.168.60.13", f.GetIP().GetSource())
			assert.Equal(t, "extEP-192.168.60.13", f.GetSource().GetPodName())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, "local", f.GetSource().GetNamespace())
			assert.Equal(t, uint32(7890), f.GetSource().GetIdentity())

			assert.Equal(t, "192.168.60.14", f.GetIP().GetDestination())
			assert.Equal(t, uint32(34182), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, "pod-192.168.60.14", f.GetDestination().GetPodName())
			assert.Equal(t, "remote", f.GetDestination().GetNamespace())
			assert.Equal(t, uint32(1234), f.GetDestination().GetIdentity())
		})
		t.Run("drop from_network unroutable", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseDropNotify{
					DropNotify: monitor.DropNotify{
						Type:       byte(monitorAPI.MessageTypeDrop),
						Version:    monitor.DropNotifyVersion3,
						ExtVersion: monitor.DropNotifyExtensionV1,
					},
					SrcNetID: 0,
					DstNetID: 100,
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{6, 7, 4, 9, 2, 3},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						SrcIP:    net.IPv4(10, 17, 60, 13),
						DstIP:    net.IPv4(192, 168, 60, 17), // unknown endpoint caused drop
					},
					&layers.TCP{
						DstPort: 34182,
						SrcPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, flowpb.Verdict_DROPPED, f.GetVerdict())

			assert.Equal(t, "192.168.60.13", f.GetIP().GetSource())
			assert.Equal(t, "extEP-192.168.60.13", f.GetSource().GetPodName())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, "local", f.GetSource().GetNamespace())
			assert.Equal(t, uint32(7890), f.GetSource().GetIdentity())

			assert.Equal(t, "192.168.60.17", f.GetIP().GetDestination())
			assert.Equal(t, uint32(34182), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, uint32(identity.ReservedIdentityWorldIPv4), f.GetDestination().GetIdentity())
		})
		t.Run("trace to_overlay", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseTraceNotify{
					TraceNotify: monitor.TraceNotify{
						Type:       byte(monitorAPI.MessageTypeTrace),
						ObsPoint:   monitorAPI.TraceToOverlay,
						Version:    monitor.TraceNotifyVersion2,
						ExtVersion: monitor.TraceNotifyExtensionV1,
						SrcLabel:   7890,
						DstLabel:   1234,
						Reason:     monitor.TraceReasonCtEstablished,
					},
					SrcNetID: 0,
					DstNetID: 0,
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{6, 7, 4, 9, 2, 3},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						SrcIP:    net.IPv4(10, 17, 60, 13),
						DstIP:    net.IPv4(10, 17, 70, 14),
					},
					&layers.TCP{
						DstPort: 34182,
						SrcPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
			assert.Equal(t, flowpb.TraceReason_ESTABLISHED, f.GetTraceReason())

			assert.Equal(t, "192.168.60.13", f.GetIP().GetSource())
			assert.Equal(t, "extEP-192.168.60.13", f.GetSource().GetPodName())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, "local", f.GetSource().GetNamespace())
			assert.Equal(t, uint32(7890), f.GetSource().GetIdentity())

			assert.Equal(t, "192.168.60.14", f.GetIP().GetDestination())
			assert.Equal(t, uint32(34182), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, "pod-192.168.60.14", f.GetDestination().GetPodName())
			assert.Equal(t, "remote", f.GetDestination().GetNamespace())
			assert.Equal(t, uint32(1234), f.GetDestination().GetIdentity())
		})
	})
	t.Run("unknown flow", func(t *testing.T) {
		t.Run("trace from_network", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseTraceNotify{
					TraceNotify: monitor.TraceNotify{
						Type:       byte(monitorAPI.MessageTypeTrace),
						ObsPoint:   monitorAPI.TraceFromNetwork,
						Version:    monitor.TraceNotifyVersion2,
						ExtVersion: monitor.TraceNotifyExtensionV1,
						Reason:     monitor.TraceReasonCtEstablished,
						Flags:      monitor.TraceNotifyFlagIsVXLAN,
					},
					SrcNetID: 0,
					DstNetID: uint16(tables.NetworkIDUnknown),
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{5, 7, 3, 4, 1, 3},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolUDP,
						SrcIP:    net.IPv4(10, 1, 1, 13),
						DstIP:    net.IPv4(10, 1, 1, 11),
					},
					&layers.UDP{
						SrcPort: 34183,
						DstPort: 8472,
					},
					&layers.VXLAN{
						VNI: 99,
					},
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{6, 7, 4, 9, 2, 3},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						SrcIP:    net.IPv4(10, 17, 70, 14),
						DstIP:    net.IPv4(10, 17, 70, 14), // destination is the source PIP as net IP
					},
					&layers.TCP{
						SrcPort: 34182,
						DstPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
			assert.Equal(t, flowpb.TraceReason_ESTABLISHED, f.GetTraceReason())

			assert.Equal(t, "10.17.70.14", f.GetIP().GetDestination())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, identity.ReservedIdentityWorldIPv4.Uint32(), f.GetDestination().GetIdentity())

			assert.Equal(t, "192.168.60.14", f.GetIP().GetSource())
			assert.Equal(t, uint32(34182), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, "pod-192.168.60.14", f.GetSource().GetPodName())
			assert.Equal(t, "remote", f.GetSource().GetNamespace())
			assert.Equal(t, uint32(1234), f.GetSource().GetIdentity())
		})
		t.Run("trace from_network attached", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseTraceNotify{
					TraceNotify: monitor.TraceNotify{
						Type:       byte(monitorAPI.MessageTypeTrace),
						ObsPoint:   monitorAPI.TraceFromNetwork,
						Version:    monitor.TraceNotifyVersion2,
						ExtVersion: monitor.TraceNotifyExtensionV1,
						Reason:     monitor.TraceReasonCtEstablished,
					},
					SrcNetID: 102,
					DstNetID: 102,
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{6, 7, 4, 9, 2, 3},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						SrcIP:    net.IPv4(10, 17, 70, 14), // source is the destination PIP as net IP
						DstIP:    net.IPv4(192, 168, 60, 14),
					},
					&layers.TCP{
						DstPort: 34182,
						SrcPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
			assert.Equal(t, flowpb.TraceReason_ESTABLISHED, f.GetTraceReason())

			assert.Equal(t, "10.17.70.14", f.GetIP().GetSource())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, identity.ReservedIdentityWorldIPv4.Uint32(), f.GetSource().GetIdentity())

			assert.Equal(t, "192.168.60.14", f.GetIP().GetDestination())
			assert.Equal(t, uint32(34182), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, "pod-192.168.60.14", f.GetDestination().GetPodName())
			assert.Equal(t, "remote", f.GetDestination().GetNamespace())
			assert.Equal(t, uint32(1234), f.GetDestination().GetIdentity())
		})
		t.Run("trace to_overlay", func(t *testing.T) {
			f := parser.decodePerfEvent(t,
				monitor.EnterpriseTraceNotify{
					TraceNotify: monitor.TraceNotify{
						Type:       byte(monitorAPI.MessageTypeTrace),
						ObsPoint:   monitorAPI.TraceToOverlay,
						Version:    monitor.TraceNotifyVersion2,
						ExtVersion: monitor.TraceNotifyExtensionV1,
						SrcLabel:   7890,
						Reason:     monitor.TraceReasonCtEstablished,
					},
					SrcNetID: 102,
					DstNetID: 0,
				},
				[]gopacket.SerializableLayer{
					&layers.Ethernet{
						SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
						DstMAC:       net.HardwareAddr{6, 7, 4, 9, 2, 3},
						EthernetType: layers.EthernetTypeIPv4,
					},
					&layers.IPv4{
						Protocol: layers.IPProtocolTCP,
						SrcIP:    net.IPv4(10, 17, 70, 14), // source is the destination PIP as net IP
						DstIP:    net.IPv4(10, 17, 70, 14),
					},
					&layers.TCP{
						DstPort: 34182,
						SrcPort: 80,
						ACK:     true,
					},
				}).GetFlow()
			require.NotNil(t, f)

			assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
			assert.Equal(t, flowpb.TraceReason_ESTABLISHED, f.GetTraceReason())

			assert.Equal(t, "10.17.70.14", f.GetIP().GetSource())
			assert.Equal(t, uint32(80), f.L4.GetTCP().GetSourcePort())
			assert.Equal(t, identity.ReservedIdentityWorldIPv4.Uint32(), f.GetSource().GetIdentity())

			assert.Equal(t, "192.168.60.14", f.GetIP().GetDestination())
			assert.Equal(t, uint32(34182), f.L4.GetTCP().GetDestinationPort())
			assert.Equal(t, "pod-192.168.60.14", f.GetDestination().GetPodName())
			assert.Equal(t, "remote", f.GetDestination().GetNamespace())
			assert.Equal(t, uint32(1234), f.GetDestination().GetIdentity())
		})
	})
}

func TestL7_Privnet(t *testing.T) {
	parser := newTestParser(t)

	txn := parser.db.WriteTxn(parser.privNetEps, parser.privNetMapEntries)

	parser.registerEPInfo("10.16.236.178", &testutils.FakeEndpointInfo{
		ID:           1234,
		Identity:     5678,
		PodName:      "pod-192.168.1.11",
		PodNamespace: "default",
		Pod: &slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				GenerateName: "foo-",
				OwnerReferences: []slim_metav1.OwnerReference{
					{
						Kind:       "ReplicaSet",
						Name:       "foo",
						Controller: ptr.To(true),
					},
				},
			},
		},
	})
	parser.registerIPCacheEntry("10.16.236.178",
		&ipcache.K8sMetadata{
			Namespace: "default",
			PodName:   "pod-192.168.1.11",
		},
		ipcache.Identity{
			ID:     5678,
			Source: source.Unspec,
		})
	parser.registerPrivnetEndpoint(txn, "net-a", 100, "pod-192.168.1.11", "192.168.1.11", "10.16.236.178")

	parser.registerEPInfo("10.16.236.179", &testutils.FakeEndpointInfo{
		ID:           2345,
		Identity:     6789,
		PodName:      "pod-192.168.1.12",
		PodNamespace: "default",
		Pod: &slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				GenerateName: "bar-",
				OwnerReferences: []slim_metav1.OwnerReference{
					{
						Kind:       "ReplicaSet",
						Name:       "bar",
						Controller: ptr.To(true),
					},
				},
			},
		},
	})
	parser.registerIPCacheEntry("10.16.236.179",
		&ipcache.K8sMetadata{
			Namespace: "default",
			PodName:   "pod-192.168.1.12",
		},
		ipcache.Identity{
			ID:     6789,
			Source: source.Unspec,
		})
	parser.registerPrivnetEndpoint(txn, "net-a", 100, "pod-192.168.1.12", "192.168.1.12", "10.16.236.179")

	parser.registerIPCacheEntry("10.17.60.13",
		&ipcache.K8sMetadata{
			Namespace: "remote",
			PodName:   "pod-192.168.60.13",
		},
		ipcache.Identity{
			ID:     7890,
			Source: source.Unspec,
		})
	parser.registerPrivnetEndpoint(txn, "net-a", 100, "pod-192.168.60.13", "192.168.60.13", "10.17.60.13")

	txn.Commit()

	t.Run("pod-to-local-pod", func(t *testing.T) {
		e, err := parser.Decode(&observerTypes.MonitorEvent{
			UUID: uuid.New(),
			Payload: &observerTypes.AgentEvent{
				Type: api.MessageTypeAccessLog,
				Message: accesslog.LogRecord{
					Type:             accesslog.TypeRequest,
					Timestamp:        "2006-01-02T15:04:05.999999999Z",
					ObservationPoint: accesslog.Ingress,
					SourceEndpoint: accesslog.EndpointInfo{
						ID:       1234,
						IPv4:     "10.16.236.178",
						Port:     38715,
						Identity: 5678,
						Labels: []labels.Label{
							{
								Key:    "local",
								Value:  "true",
								Source: "k8s",
							},
						},
					},
					DestinationEndpoint: accesslog.EndpointInfo{
						ID:       2345,
						IPv4:     "10.16.236.179",
						Port:     8080,
						Identity: 6789,
					},
					IPVersion:         accesslog.VersionIPv4,
					Verdict:           accesslog.VerdictForwarded,
					TransportProtocol: accesslog.TransportProtocol(u8proto.TCP),
					ServiceInfo:       nil,
					DropReason:        nil,
					HTTP: &accesslog.LogRecordHTTP{
						Method: "PUT",
						URL: func() *url.URL {
							u, _ := url.Parse("/foobar")
							return u
						}(),
						Protocol: "HTTP/1.1",
					},
				},
			},
		})
		require.NoError(t, err)

		f := e.GetFlow()
		require.NotNil(t, f)

		assert.Equal(t, "/foobar", f.GetL7().GetHttp().GetUrl())

		assert.Equal(t, "192.168.1.11", f.GetIP().GetSource())
		assert.Equal(t, uint32(38715), f.L4.GetTCP().GetSourcePort())
		assert.Equal(t, "pod-192.168.1.11", f.GetSource().GetPodName())
		assert.Equal(t, "default", f.GetSource().GetNamespace())
		assert.Equal(t, uint32(5678), f.GetSource().GetIdentity())
		if assert.Len(t, f.GetSource().GetWorkloads(), 1) {
			assert.Equal(t, "foo", f.GetSource().GetWorkloads()[0].Name)
		}

		assert.Equal(t, "192.168.1.12", f.GetIP().GetDestination())
		assert.Equal(t, uint32(8080), f.L4.GetTCP().GetDestinationPort())
		assert.Equal(t, "pod-192.168.1.12", f.GetDestination().GetPodName())
		assert.Equal(t, "default", f.GetDestination().GetNamespace())
		assert.Equal(t, uint32(6789), f.GetDestination().GetIdentity())
		if assert.Len(t, f.GetDestination().GetWorkloads(), 1) {
			assert.Equal(t, "bar", f.GetDestination().GetWorkloads()[0].Name)
		}
	})
	t.Run("pod-to-remote-pod", func(t *testing.T) {
		e, err := parser.Decode(&observerTypes.MonitorEvent{
			UUID: uuid.New(),
			Payload: &observerTypes.AgentEvent{
				Type: api.MessageTypeAccessLog,
				Message: accesslog.LogRecord{
					Type:             accesslog.TypeResponse,
					Timestamp:        "2006-01-02T15:04:05.999999999Z",
					ObservationPoint: accesslog.Ingress,
					SourceEndpoint: accesslog.EndpointInfo{
						ID:       1234,
						IPv4:     "10.16.236.178",
						Port:     38115,
						Identity: 5678,
						Labels: []labels.Label{
							{
								Key:    "local",
								Value:  "true",
								Source: "k8s",
							},
						},
					},
					DestinationEndpoint: accesslog.EndpointInfo{
						IPv4:     "10.17.60.13",
						Port:     8080,
						Identity: 7890,
					},
					IPVersion:         accesslog.VersionIPv4,
					Verdict:           accesslog.VerdictForwarded,
					TransportProtocol: accesslog.TransportProtocol(u8proto.TCP),
					ServiceInfo:       nil,
					DropReason:        nil,
					HTTP: &accesslog.LogRecordHTTP{
						Code:   418,
						Method: "POST",
						URL: func() *url.URL {
							u, _ := url.Parse("/buzz")
							return u
						}(),
						Protocol: "HTTP/1.1",
					},
				},
			},
		})
		require.NoError(t, err)

		f := e.GetFlow()
		require.NotNil(t, f)

		assert.Equal(t, "/buzz", f.GetL7().GetHttp().GetUrl())
		assert.Equal(t, uint32(418), f.GetL7().GetHttp().GetCode())

		assert.Equal(t, "192.168.1.11", f.GetIP().GetSource())
		assert.Equal(t, uint32(38115), f.L4.GetTCP().GetSourcePort())
		assert.Equal(t, "pod-192.168.1.11", f.GetSource().GetPodName())
		assert.Equal(t, "default", f.GetSource().GetNamespace())
		assert.Equal(t, uint32(5678), f.GetSource().GetIdentity())
		if assert.Len(t, f.GetSource().GetWorkloads(), 1) {
			assert.Equal(t, "foo", f.GetSource().GetWorkloads()[0].Name)
		}

		assert.Equal(t, "192.168.60.13", f.GetIP().GetDestination())
		assert.Equal(t, uint32(8080), f.L4.GetTCP().GetDestinationPort())
		assert.Equal(t, "pod-192.168.60.13", f.GetDestination().GetPodName())
		assert.Equal(t, "remote", f.GetDestination().GetNamespace())
		assert.Equal(t, uint32(7890), f.GetDestination().GetIdentity())
	})
}

type testParser struct {
	*PrivnetAdapter

	privNetEps        statedb.RWTable[tables.Endpoint]
	privNetMapentries statedb.RWTable[*tables.MapEntry]

	epByIP map[netip.Addr]getters.EndpointInfo
	epByID map[uint64]getters.EndpointInfo

	idntById map[uint32]*identity.Identity

	fqdnCache map[uint32]map[string][]string

	ipcacheK8s map[netip.Addr]*ipcache.K8sMetadata
	ipcacheID  map[netip.Addr]ipcache.Identity

	services map[netip.AddrPort]*flowpb.Service
}

func newTestParser(t testing.TB) testParser {
	t.Helper()

	db := statedb.New()

	eps, err := tables.NewEndpointsTable(db)
	require.NoError(t, err)
	mes, err := tables.NewMapEntriesTable(db)
	require.NoError(t, err)

	adptr := &PrivnetAdapter{
		db:                db,
		privNetEps:        eps,
		privNetMapEntries: mes,
	}
	tp := testParser{
		PrivnetAdapter:    adptr,
		privNetEps:        eps,
		privNetMapentries: mes,
		epByIP:            map[netip.Addr]getters.EndpointInfo{},
		epByID:            map[uint64]getters.EndpointInfo{},
		idntById:          map[uint32]*identity.Identity{},
		fqdnCache:         map[uint32]map[string][]string{},
		ipcacheK8s:        map[netip.Addr]*ipcache.K8sMetadata{},
		ipcacheID:         map[netip.Addr]ipcache.Identity{},
		services:          map[netip.AddrPort]*flowpb.Service{},
	}

	p, err := parser.New(hivetest.Logger(t),
		&testutils.FakeEndpointGetter{
			OnGetEndpointInfo: func(ip netip.Addr) (getters.EndpointInfo, bool) {
				info, ok := tp.epByIP[ip]
				return info, ok
			},
			OnGetEndpointInfoByID: func(id uint16) (getters.EndpointInfo, bool) {
				info, ok := tp.epByID[uint64(id)]
				return info, ok
			},
		},
		&testutils.FakeIdentityGetter{
			OnGetIdentity: func(securityIdentity uint32) (*identity.Identity, error) {
				idn, ok := tp.idntById[securityIdentity]
				if !ok {
					return idn, fmt.Errorf("identity %d not found", securityIdentity)
				}
				return idn, nil
			},
		},
		&testutils.FakeFQDNCache{
			OnGetNamesOf: func(epID uint32, ip netip.Addr) []string {
				cache, ok := tp.fqdnCache[epID]
				if !ok {
					return nil
				}
				return cache[ip.String()]
			},
		},
		&testutils.FakeIPGetter{
			OnGetK8sMetadata: func(ip netip.Addr) *ipcache.K8sMetadata {
				return tp.ipcacheK8s[ip]
			},
			OnLookupSecIDByIP: func(ip netip.Addr) (ipcache.Identity, bool) {
				id, ok := tp.ipcacheID[ip]
				return id, ok
			},
		},
		&testutils.FakeServiceGetter{
			OnGetServiceByAddr: func(ip netip.Addr, port uint16) *flowpb.Service {
				return tp.services[netip.AddrPortFrom(ip, port)]
			},
		},
		&testutils.NoopLinkGetter, nil, adptr.parserOpts)
	require.NoError(t, err)

	adptr.parser = p

	return tp
}

func (tp *testParser) registerEPInfo(ip string, info getters.EndpointInfo) {
	tp.epByIP[netip.MustParseAddr(ip)] = info
	tp.epByID[info.GetID()] = info
}

func (tp *testParser) registerFQDN(epID uint32, ip string, fqdns []string) {
	_, ok := tp.fqdnCache[epID]
	if !ok {
		tp.fqdnCache[epID] = map[string][]string{}
	}
	tp.fqdnCache[epID][ip] = fqdns
}

func (tp *testParser) registerIPCacheEntry(ip string, k8s *ipcache.K8sMetadata, id ipcache.Identity) {
	tp.ipcacheK8s[netip.MustParseAddr(ip)] = k8s
	tp.ipcacheID[netip.MustParseAddr(ip)] = id
}

func (tp *testParser) registerService(ip string, port uint16, svc *flowpb.Service) {
	tp.services[netip.AddrPortFrom(netip.MustParseAddr(ip), port)] = svc
}

func (tp *testParser) registerPrivnetEndpoint(txn statedb.WriteTxn, networkName tables.NetworkName, id tables.NetworkID, name string, netIP string, podIP string, inactivePodIPs ...string) {
	for _, ip := range append(inactivePodIPs, podIP) {
		tp.privNetEps.Insert(txn, tables.Endpoint{
			Endpoint: &kvstore.Endpoint{
				IP:   netip.MustParseAddr(ip),
				Name: name,
				Network: kvstore.Network{
					Name: string(networkName),
					IP:   netip.MustParseAddr(netIP),
				},
			},
		})
	}
	tp.privNetMapentries.Insert(txn, &tables.MapEntry{
		Type: tables.MapEntryTypeEndpoint,
		Target: tables.MapEntryTarget{
			NetworkName: networkName,
			ID: tables.SubnetIDPair{
				Network: id,
			},
			CIDR: netip.MustParsePrefix(netIP + "/32"),
		},
		Routing: tables.MapEntryRouting{
			NextHop: netip.MustParseAddr(podIP),
		},
	})
}

func (tp *testParser) decodePerfEvent(t testing.TB, perfEvent any, lay []gopacket.SerializableLayer) *v1.Event {
	t.Helper()

	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.NativeEndian, perfEvent)
	require.NoError(t, err)
	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths: true,
	}, lay...)
	require.NoError(t, err)
	buf.Write(buffer.Bytes())
	require.NoError(t, err)

	ev, err := tp.Decode(&observerTypes.MonitorEvent{
		UUID: uuid.New(),
		Payload: &observerTypes.PerfEvent{
			Data: buf.Bytes(),
		},
	})
	require.NoError(t, err)
	return ev
}
