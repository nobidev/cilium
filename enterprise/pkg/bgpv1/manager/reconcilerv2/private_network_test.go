// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"context"
	"log/slog"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/fake"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/vni"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestPrivateNetworkReconciler(t *testing.T) {
	var (
		testASN             = int64(65001)
		testRouterID        = "1.2.3.4"
		testVxlanDeviceMAC1 = "01:02:03:04:05:06"
		testVxlanDeviceMAC2 = "06:05:04:03:02:01"

		vrf1PrivNetConfig = &v1alpha1.IsovalentBGPVRFConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: "vrf1-config",
			},
			Spec: v1alpha1.IsovalentBGPVRFConfigSpec{
				Families: []v2alpha1.CiliumBGPFamilyWithAdverts{
					{
						CiliumBGPFamily: v2alpha1.CiliumBGPFamily{Afi: "ipv4", Safi: "unicast"},
						Advertisements:  &slimv1.LabelSelector{MatchLabels: vrf1AdvertLabel},
					},
				},
			},
		}
		vrf1PrivNetConfigDualStack = &v1alpha1.IsovalentBGPVRFConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: "vrf1-config",
			},
			Spec: v1alpha1.IsovalentBGPVRFConfigSpec{
				Families: []v2alpha1.CiliumBGPFamilyWithAdverts{
					{
						CiliumBGPFamily: v2alpha1.CiliumBGPFamily{Afi: "ipv4", Safi: "unicast"},
						Advertisements:  &slimv1.LabelSelector{MatchLabels: vrf1AdvertLabel},
					},
					{
						CiliumBGPFamily: v2alpha1.CiliumBGPFamily{Afi: "ipv6", Safi: "unicast"},
						Advertisements:  &slimv1.LabelSelector{MatchLabels: vrf1AdvertLabel},
					},
				},
			},
		}
		vrf2PrivNetConfig = &v1alpha1.IsovalentBGPVRFConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: "vrf2-config",
			},
			Spec: v1alpha1.IsovalentBGPVRFConfigSpec{
				Families: []v2alpha1.CiliumBGPFamilyWithAdverts{
					{
						CiliumBGPFamily: v2alpha1.CiliumBGPFamily{Afi: "ipv4", Safi: "unicast"},
						Advertisements:  &slimv1.LabelSelector{MatchLabels: vrf2AdvertLabel},
					},
				},
			},
		}

		vrf1PrivNetAdvert = &v1.IsovalentBGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "vrf1-advert",
				Labels: vrf1AdvertLabel,
			},
			Spec: v1.IsovalentBGPAdvertisementSpec{
				Advertisements: []v1.BGPAdvertisement{{AdvertisementType: v1.BGPPrivateNetworkAdvert}},
			},
		}
		vrf2PrivNetAdvert = &v1.IsovalentBGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "vrf2-advert",
				Labels: vrf2AdvertLabel,
			},
			Spec: v1.IsovalentBGPAdvertisementSpec{
				Advertisements: []v1.BGPAdvertisement{{AdvertisementType: v1.BGPPrivateNetworkAdvert}},
			},
		}

		v4OnlyPrivnetAdvertisement = FamilyAdvertisements{
			{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{{AdvertisementType: v1.BGPPrivateNetworkAdvert}},
		}
		dualStackPrivnetAdvertisement = FamilyAdvertisements{
			{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{{AdvertisementType: v1.BGPPrivateNetworkAdvert}},
			{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{{AdvertisementType: v1.BGPPrivateNetworkAdvert}},
		}

		privNet1Name        = "privnet-1"
		privNet2Name        = "privnet-2"
		privNet1            = tables.PrivateNetwork{Name: tables.NetworkName(privNet1Name), VNI: vni.MustFromUint32(101)}
		privNet1NoVNI       = tables.PrivateNetwork{Name: tables.NetworkName(privNet1Name)}
		privNet1ModifiedVNI = tables.PrivateNetwork{Name: tables.NetworkName(privNet1Name), VNI: vni.MustFromUint32(500)}
		privNet2            = tables.PrivateNetwork{Name: tables.NetworkName(privNet2Name), VNI: vni.MustFromUint32(201)}

		privNetVRF1Config = v1.IsovalentBGPNodeVRF{
			ConfigRef:         &vrf1PrivNetConfig.Name,
			PrivateNetworkRef: &v1.BGPPrivateNetworkReference{Name: privNet1Name},
		}
		privNetVRF2Config = v1.IsovalentBGPNodeVRF{
			ConfigRef:         &vrf2PrivNetConfig.Name,
			PrivateNetworkRef: &v1.BGPPrivateNetworkReference{Name: privNet2Name},
		}

		privNetBGPNodeInstance = func(vrfs []v1.IsovalentBGPNodeVRF) *v1.IsovalentBGPNodeInstance {
			return &v1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](testASN),
				RouterID: ptr.To(testRouterID),
				VRFs:     vrfs,
			}
		}

		privNet1EP1 = &tables.LocalWorkload{
			EndpointID: 1,
			Endpoint:   v1alpha1.PrivateNetworkEndpointSliceEndpoint{Name: "pn1ep1"},
			Interface: v1alpha1.PrivateNetworkEndpointSliceInterface{
				Network:    privNet1Name,
				Addressing: v1alpha1.PrivateNetworkEndpointAddressing{IPv4: "10.10.10.1"},
			},
		}
		privNet1EP2 = &tables.LocalWorkload{
			EndpointID: 2,
			Endpoint:   v1alpha1.PrivateNetworkEndpointSliceEndpoint{Name: "pn1ep2"},
			Interface: v1alpha1.PrivateNetworkEndpointSliceInterface{
				Network:    privNet1Name,
				Addressing: v1alpha1.PrivateNetworkEndpointAddressing{IPv4: "10.10.10.2", IPv6: "fd00::2"},
			},
		}

		privNet2EP1 = &tables.LocalWorkload{
			EndpointID: 3,
			Endpoint:   v1alpha1.PrivateNetworkEndpointSliceEndpoint{Name: "pn2ep1"},
			Interface: v1alpha1.PrivateNetworkEndpointSliceInterface{
				Network:    privNet2Name,
				Addressing: v1alpha1.PrivateNetworkEndpointAddressing{IPv4: "20.20.20.1"},
			},
		}
		privNet2EP2 = &tables.LocalWorkload{
			EndpointID: 4,
			Endpoint:   v1alpha1.PrivateNetworkEndpointSliceEndpoint{Name: "pn2ep2"},
			Interface: v1alpha1.PrivateNetworkEndpointSliceInterface{
				Network:    privNet2Name,
				Addressing: v1alpha1.PrivateNetworkEndpointAddressing{IPv4: "20.20.20.2"},
			},
		}
	)

	vrf1RD, err := bgp.ParseRouteDistinguisher(testRouterID + ":1")
	require.NoError(t, err)
	vrf1EP1NLRI := bgp.NewEVPNIPPrefixRoute(vrf1RD, bgp.EthernetSegmentIdentifier{}, 0, 32, privNet1EP1.Interface.Addressing.IPv4, "0.0.0.0", privNet1.VNI.AsUint32())
	vrf1EP1NLRIVNI500 := bgp.NewEVPNIPPrefixRoute(vrf1RD, bgp.EthernetSegmentIdentifier{}, 0, 32, privNet1EP1.Interface.Addressing.IPv4, "0.0.0.0", privNet1ModifiedVNI.VNI.AsUint32())
	vrf1EP2IPv4NLRI := bgp.NewEVPNIPPrefixRoute(vrf1RD, bgp.EthernetSegmentIdentifier{}, 0, 32, privNet1EP2.Interface.Addressing.IPv4, "0.0.0.0", privNet1.VNI.AsUint32())
	vrf1EP2IPv6NLRI := bgp.NewEVPNIPPrefixRoute(vrf1RD, bgp.EthernetSegmentIdentifier{}, 0, 128, privNet1EP2.Interface.Addressing.IPv6, "0.0.0.0", privNet1.VNI.AsUint32())

	vrf2RD, err := bgp.ParseRouteDistinguisher(testRouterID + ":2")
	require.NoError(t, err)
	vrf2EP1NLRI := bgp.NewEVPNIPPrefixRoute(vrf2RD, bgp.EthernetSegmentIdentifier{}, 0, 32, privNet2EP1.Interface.Addressing.IPv4, "0.0.0.0", privNet2.VNI.AsUint32())
	vrf2EP2NLRI := bgp.NewEVPNIPPrefixRoute(vrf2RD, bgp.EthernetSegmentIdentifier{}, 0, 32, privNet2EP2.Interface.Addressing.IPv4, "0.0.0.0", privNet2.VNI.AsUint32())

	tests := []struct {
		name                   string
		bgpNodeInstance        *v1.IsovalentBGPNodeInstance
		vrfConfigs             []*v1alpha1.IsovalentBGPVRFConfig
		adverts                []*v1.IsovalentBGPAdvertisement
		upsertPrivateNetworks  []tables.PrivateNetwork
		deletePrivateNetworks  []tables.PrivateNetwork
		upsertPrivNetWorkloads []*tables.LocalWorkload
		deletePrivNetWorkloads []*tables.LocalWorkload
		vxlanDeviceMac         string

		expectedAdverts VRFAdvertisements
		expectedPaths   vrfSimplePathsMap
	}{
		{
			name:            "add VRF 1, no private network, advertise 0 paths",
			bgpNodeInstance: privNetBGPNodeInstance([]v1.IsovalentBGPNodeVRF{privNetVRF1Config}),
			vrfConfigs:      []*v1alpha1.IsovalentBGPVRFConfig{vrf1PrivNetConfig},
			adverts:         []*v1.IsovalentBGPAdvertisement{vrf1PrivNetAdvert},
			expectedAdverts: VRFAdvertisements{
				privNet1Name: v4OnlyPrivnetAdvertisement,
			},
			expectedPaths: vrfSimplePathsMap{},
		},
		{
			name:                  "add private network 1, no workloads, advertise 0 paths",
			bgpNodeInstance:       privNetBGPNodeInstance([]v1.IsovalentBGPNodeVRF{privNetVRF1Config}),
			vrfConfigs:            []*v1alpha1.IsovalentBGPVRFConfig{vrf1PrivNetConfig},
			adverts:               []*v1.IsovalentBGPAdvertisement{vrf1PrivNetAdvert},
			upsertPrivateNetworks: []tables.PrivateNetwork{privNet1},
			expectedAdverts: VRFAdvertisements{
				privNet1Name: v4OnlyPrivnetAdvertisement,
			},
			expectedPaths: vrfSimplePathsMap{},
		},
		{
			name:                   "add workload in private network 1, vxlan device MAC unknown, advertise 0 paths",
			bgpNodeInstance:        privNetBGPNodeInstance([]v1.IsovalentBGPNodeVRF{privNetVRF1Config}),
			vrfConfigs:             []*v1alpha1.IsovalentBGPVRFConfig{vrf1PrivNetConfig},
			adverts:                []*v1.IsovalentBGPAdvertisement{vrf1PrivNetAdvert},
			upsertPrivNetWorkloads: []*tables.LocalWorkload{privNet1EP1},
			expectedAdverts: VRFAdvertisements{
				privNet1Name: v4OnlyPrivnetAdvertisement,
			},
			expectedPaths: vrfSimplePathsMap{},
		},
		{
			name:            "add vxlan device MAC, advertise 1 path",
			bgpNodeInstance: privNetBGPNodeInstance([]v1.IsovalentBGPNodeVRF{privNetVRF1Config}),
			vrfConfigs:      []*v1alpha1.IsovalentBGPVRFConfig{vrf1PrivNetConfig},
			adverts:         []*v1.IsovalentBGPAdvertisement{vrf1PrivNetAdvert},
			vxlanDeviceMac:  testVxlanDeviceMAC1,
			expectedAdverts: VRFAdvertisements{
				privNet1Name: v4OnlyPrivnetAdvertisement,
			},
			expectedPaths: vrfSimplePathsMap{
				privNet1Name: resourceAFSimplePathsMap{
					resource.Key{Name: privNet1EP1.Endpoint.Name}: afSimplePathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: []string{vrf1EP1NLRI.String()},
					},
				},
			},
		},
		{
			name:                   "add VRF 2 and private network 2 with workload, advertise 2 paths",
			bgpNodeInstance:        privNetBGPNodeInstance([]v1.IsovalentBGPNodeVRF{privNetVRF1Config, privNetVRF2Config}),
			vrfConfigs:             []*v1alpha1.IsovalentBGPVRFConfig{vrf1PrivNetConfig, vrf2PrivNetConfig},
			adverts:                []*v1.IsovalentBGPAdvertisement{vrf1PrivNetAdvert, vrf2PrivNetAdvert},
			upsertPrivateNetworks:  []tables.PrivateNetwork{privNet2},
			upsertPrivNetWorkloads: []*tables.LocalWorkload{privNet2EP1},
			vxlanDeviceMac:         testVxlanDeviceMAC1,
			expectedAdverts: VRFAdvertisements{
				privNet1Name: v4OnlyPrivnetAdvertisement,
				privNet2Name: v4OnlyPrivnetAdvertisement,
			},
			expectedPaths: vrfSimplePathsMap{
				privNet1Name: resourceAFSimplePathsMap{
					resource.Key{Name: privNet1EP1.Endpoint.Name}: afSimplePathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: []string{vrf1EP1NLRI.String()},
					},
				},
				privNet2Name: resourceAFSimplePathsMap{
					resource.Key{Name: privNet2EP1.Endpoint.Name}: afSimplePathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: []string{vrf2EP1NLRI.String()},
					},
				},
			},
		},
		{
			name:                   "add another workload to private network 2, advertise 3 paths",
			bgpNodeInstance:        privNetBGPNodeInstance([]v1.IsovalentBGPNodeVRF{privNetVRF1Config, privNetVRF2Config}),
			vrfConfigs:             []*v1alpha1.IsovalentBGPVRFConfig{vrf1PrivNetConfig, vrf2PrivNetConfig},
			adverts:                []*v1.IsovalentBGPAdvertisement{vrf1PrivNetAdvert, vrf2PrivNetAdvert},
			upsertPrivNetWorkloads: []*tables.LocalWorkload{privNet2EP2},
			vxlanDeviceMac:         testVxlanDeviceMAC1,
			expectedAdverts: VRFAdvertisements{
				privNet1Name: v4OnlyPrivnetAdvertisement,
				privNet2Name: v4OnlyPrivnetAdvertisement,
			},
			expectedPaths: vrfSimplePathsMap{
				privNet1Name: resourceAFSimplePathsMap{
					resource.Key{Name: privNet1EP1.Endpoint.Name}: afSimplePathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: []string{vrf1EP1NLRI.String()},
					},
				},
				privNet2Name: resourceAFSimplePathsMap{
					resource.Key{Name: privNet2EP1.Endpoint.Name}: afSimplePathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: []string{vrf2EP1NLRI.String()},
					},
					resource.Key{Name: privNet2EP2.Endpoint.Name}: afSimplePathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: []string{vrf2EP2NLRI.String()},
					},
				},
			},
		},
		{
			name:                   "delete workload from private network 2, advertise 2 paths",
			bgpNodeInstance:        privNetBGPNodeInstance([]v1.IsovalentBGPNodeVRF{privNetVRF1Config, privNetVRF2Config}),
			vrfConfigs:             []*v1alpha1.IsovalentBGPVRFConfig{vrf1PrivNetConfig, vrf2PrivNetConfig},
			adverts:                []*v1.IsovalentBGPAdvertisement{vrf1PrivNetAdvert, vrf2PrivNetAdvert},
			deletePrivNetWorkloads: []*tables.LocalWorkload{privNet2EP1},
			vxlanDeviceMac:         testVxlanDeviceMAC1,
			expectedAdverts: VRFAdvertisements{
				privNet1Name: v4OnlyPrivnetAdvertisement,
				privNet2Name: v4OnlyPrivnetAdvertisement,
			},
			expectedPaths: vrfSimplePathsMap{
				privNet1Name: resourceAFSimplePathsMap{
					resource.Key{Name: privNet1EP1.Endpoint.Name}: afSimplePathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: []string{vrf1EP1NLRI.String()},
					},
				},
				privNet2Name: resourceAFSimplePathsMap{
					resource.Key{Name: privNet2EP2.Endpoint.Name}: afSimplePathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: []string{vrf2EP2NLRI.String()},
					},
				},
			},
		},
		{
			name:            "delete VRF 2 from BGP config, advertise 1 path",
			bgpNodeInstance: privNetBGPNodeInstance([]v1.IsovalentBGPNodeVRF{privNetVRF1Config}),
			vrfConfigs:      []*v1alpha1.IsovalentBGPVRFConfig{vrf1PrivNetConfig},
			adverts:         []*v1.IsovalentBGPAdvertisement{vrf1PrivNetAdvert},
			vxlanDeviceMac:  testVxlanDeviceMAC1,
			expectedAdverts: VRFAdvertisements{
				privNet1Name: v4OnlyPrivnetAdvertisement,
			},
			expectedPaths: vrfSimplePathsMap{
				privNet1Name: resourceAFSimplePathsMap{
					resource.Key{Name: privNet1EP1.Endpoint.Name}: afSimplePathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: []string{vrf1EP1NLRI.String()},
					},
				},
			},
		},
		{
			name:                   "add dual-stack workload to private network 1, keep only IPv4 AF in VRF config, advertise 2 IPv4 paths",
			bgpNodeInstance:        privNetBGPNodeInstance([]v1.IsovalentBGPNodeVRF{privNetVRF1Config}),
			vrfConfigs:             []*v1alpha1.IsovalentBGPVRFConfig{vrf1PrivNetConfig},
			adverts:                []*v1.IsovalentBGPAdvertisement{vrf1PrivNetAdvert},
			upsertPrivNetWorkloads: []*tables.LocalWorkload{privNet1EP2},
			vxlanDeviceMac:         testVxlanDeviceMAC1,
			expectedAdverts: VRFAdvertisements{
				privNet1Name: v4OnlyPrivnetAdvertisement,
			},
			expectedPaths: vrfSimplePathsMap{
				privNet1Name: resourceAFSimplePathsMap{
					resource.Key{Name: privNet1EP1.Endpoint.Name}: afSimplePathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: []string{vrf1EP1NLRI.String()},
					},
					resource.Key{Name: privNet1EP2.Endpoint.Name}: afSimplePathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: []string{vrf1EP2IPv4NLRI.String()},
					},
				},
			},
		},
		{
			name:            "add IPv6 AF into VRF config, advertise 2 IPv4 paths + 1 IPv6 path",
			bgpNodeInstance: privNetBGPNodeInstance([]v1.IsovalentBGPNodeVRF{privNetVRF1Config}),
			vrfConfigs:      []*v1alpha1.IsovalentBGPVRFConfig{vrf1PrivNetConfigDualStack},
			adverts:         []*v1.IsovalentBGPAdvertisement{vrf1PrivNetAdvert},
			vxlanDeviceMac:  testVxlanDeviceMAC1,
			expectedAdverts: VRFAdvertisements{
				privNet1Name: dualStackPrivnetAdvertisement,
			},
			expectedPaths: vrfSimplePathsMap{
				privNet1Name: resourceAFSimplePathsMap{
					resource.Key{Name: privNet1EP1.Endpoint.Name}: afSimplePathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: []string{vrf1EP1NLRI.String()},
					},
					resource.Key{Name: privNet1EP2.Endpoint.Name}: afSimplePathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: []string{vrf1EP2IPv4NLRI.String()},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: []string{vrf1EP2IPv6NLRI.String()},
					},
				},
			},
		},
		{
			name:                  "update private network 1 - delete VNI, withdraw all routes",
			bgpNodeInstance:       privNetBGPNodeInstance([]v1.IsovalentBGPNodeVRF{privNetVRF1Config}),
			vrfConfigs:            []*v1alpha1.IsovalentBGPVRFConfig{vrf1PrivNetConfigDualStack},
			adverts:               []*v1.IsovalentBGPAdvertisement{vrf1PrivNetAdvert},
			upsertPrivateNetworks: []tables.PrivateNetwork{privNet1NoVNI},
			vxlanDeviceMac:        testVxlanDeviceMAC1,
			expectedAdverts: VRFAdvertisements{
				privNet1Name: dualStackPrivnetAdvertisement,
			},
			expectedPaths: vrfSimplePathsMap{},
		},
		{
			name:                  "update private network 1 - re-add VNI, advertise all routes",
			bgpNodeInstance:       privNetBGPNodeInstance([]v1.IsovalentBGPNodeVRF{privNetVRF1Config}),
			vrfConfigs:            []*v1alpha1.IsovalentBGPVRFConfig{vrf1PrivNetConfigDualStack},
			adverts:               []*v1.IsovalentBGPAdvertisement{vrf1PrivNetAdvert},
			upsertPrivateNetworks: []tables.PrivateNetwork{privNet1},
			vxlanDeviceMac:        testVxlanDeviceMAC1,
			expectedAdverts: VRFAdvertisements{
				privNet1Name: dualStackPrivnetAdvertisement,
			},
			expectedPaths: vrfSimplePathsMap{
				privNet1Name: resourceAFSimplePathsMap{
					resource.Key{Name: privNet1EP1.Endpoint.Name}: afSimplePathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: []string{vrf1EP1NLRI.String()},
					},
					resource.Key{Name: privNet1EP2.Endpoint.Name}: afSimplePathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: []string{vrf1EP2IPv4NLRI.String()},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: []string{vrf1EP2IPv6NLRI.String()},
					},
				},
			},
		},
		{
			name:                   "delete workload 2 from private network 1, advertise 1 path",
			bgpNodeInstance:        privNetBGPNodeInstance([]v1.IsovalentBGPNodeVRF{privNetVRF1Config}),
			vrfConfigs:             []*v1alpha1.IsovalentBGPVRFConfig{vrf1PrivNetConfigDualStack},
			adverts:                []*v1.IsovalentBGPAdvertisement{vrf1PrivNetAdvert},
			deletePrivNetWorkloads: []*tables.LocalWorkload{privNet1EP2},
			vxlanDeviceMac:         testVxlanDeviceMAC1,
			expectedAdverts: VRFAdvertisements{
				privNet1Name: dualStackPrivnetAdvertisement,
			},
			expectedPaths: vrfSimplePathsMap{
				privNet1Name: resourceAFSimplePathsMap{
					resource.Key{Name: privNet1EP1.Endpoint.Name}: afSimplePathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: []string{vrf1EP1NLRI.String()},
					},
				},
			},
		},
		{
			name:                  "change VNI in private network 1, advertise 1 path with modified VNI",
			bgpNodeInstance:       privNetBGPNodeInstance([]v1.IsovalentBGPNodeVRF{privNetVRF1Config}),
			vrfConfigs:            []*v1alpha1.IsovalentBGPVRFConfig{vrf1PrivNetConfigDualStack},
			adverts:               []*v1.IsovalentBGPAdvertisement{vrf1PrivNetAdvert},
			upsertPrivateNetworks: []tables.PrivateNetwork{privNet1ModifiedVNI},
			vxlanDeviceMac:        testVxlanDeviceMAC1,
			expectedAdverts: VRFAdvertisements{
				privNet1Name: dualStackPrivnetAdvertisement,
			},
			expectedPaths: vrfSimplePathsMap{
				privNet1Name: resourceAFSimplePathsMap{
					resource.Key{Name: privNet1EP1.Endpoint.Name}: afSimplePathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: []string{vrf1EP1NLRIVNI500.String()},
					},
				},
			},
		},
		{
			name:                  "change vxlan device MAC, advertise 1 path with modified routers MAC",
			bgpNodeInstance:       privNetBGPNodeInstance([]v1.IsovalentBGPNodeVRF{privNetVRF1Config}),
			vrfConfigs:            []*v1alpha1.IsovalentBGPVRFConfig{vrf1PrivNetConfigDualStack},
			adverts:               []*v1.IsovalentBGPAdvertisement{vrf1PrivNetAdvert},
			upsertPrivateNetworks: []tables.PrivateNetwork{privNet1ModifiedVNI},
			vxlanDeviceMac:        testVxlanDeviceMAC2,
			expectedAdverts: VRFAdvertisements{
				privNet1Name: dualStackPrivnetAdvertisement,
			},
			expectedPaths: vrfSimplePathsMap{
				privNet1Name: resourceAFSimplePathsMap{
					resource.Key{Name: privNet1EP1.Endpoint.Name}: afSimplePathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: []string{vrf1EP1NLRIVNI500.String()},
					},
				},
			},
		},
	}

	req := require.New(t)
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	// resource store mocks
	vrfConfigMockStore := store.NewMockBGPCPResourceStore[*v1alpha1.IsovalentBGPVRFConfig]()
	advertMockStore := store.NewMockBGPCPResourceStore[*v1.IsovalentBGPAdvertisement]()
	isoAdverts := &IsovalentAdvertisement{
		logger:  logger,
		adverts: advertMockStore,
		vrfs:    vrfConfigMockStore,
	}

	// init test statedb
	db := statedb.New()
	privateNetworksTable, err := tables.NewPrivateNetworksTable(db)
	req.NoError(err)
	privNetWorkloadsTable, err := tables.NewLocalWorkloadsTable(db)
	req.NoError(err)

	svcVRFReconciler := &PrivateNetworkReconciler{
		logger:           logger,
		db:               db,
		privateNetworks:  privateNetworksTable,
		privNetWorkloads: privNetWorkloadsTable,
		adverts:          isoAdverts,
		evpnPaths:        &evpnPaths{},
		metadata:         make(map[string]privateNetworkReconcilerMetadata),
	}

	testOSSBGPInstance := &instance.BGPInstance{
		Name:   "fake-instance",
		Router: fake.NewEnterpriseFakeRouter(),
	}
	testOSSBGPInstance.Global = types.BGPGlobal{
		ASN:      uint32(testASN),
		RouterID: testRouterID,
	}
	testBGPInstance := &EnterpriseBGPInstance{
		Name:   testOSSBGPInstance.Name,
		Router: upgradeRouter(testOSSBGPInstance.Router),
		Global: testOSSBGPInstance.Global,
	}
	svcVRFReconciler.Init(testOSSBGPInstance)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// upsert VRF configs and advertisements
			for _, vrfConfig := range tt.vrfConfigs {
				vrfConfigMockStore.Upsert(vrfConfig)
			}
			for _, advert := range tt.adverts {
				advertMockStore.Upsert(advert)
			}

			tx := db.WriteTxn(privateNetworksTable, privNetWorkloadsTable)
			// upsert/delete privnets & privnet workloads in statedb
			for _, privNet := range tt.upsertPrivateNetworks {
				_, _, err = privateNetworksTable.Insert(tx, privNet)
				req.NoError(err)
			}
			for _, privNet := range tt.deletePrivateNetworks {
				_, _, err = privateNetworksTable.Delete(tx, privNet)
				req.NoError(err)
			}
			for _, w := range tt.upsertPrivNetWorkloads {
				_, _, err = privNetWorkloadsTable.Insert(tx, w)
				req.NoError(err)
			}
			for _, w := range tt.deletePrivNetWorkloads {
				_, _, err = privNetWorkloadsTable.Delete(tx, w)
				req.NoError(err)
			}
			tx.Commit()

			// upsert vxlan device MAC
			svcVRFReconciler.evpnPaths.vxlanDeviceMAC = tt.vxlanDeviceMac

			// update BGP node instance config
			svcVRFReconciler.upgrader = newUpgraderMock(tt.bgpNodeInstance)

			// reconcile twice to test idempotency
			for i := 0; i < 2; i++ {
				err := svcVRFReconciler.Reconcile(context.Background(), reconciler.ReconcileParams{
					BGPInstance: testOSSBGPInstance,
					CiliumNode:  testCiliumNodeConfig,
				})
				req.NoError(err)
			}

			// check if the expected metadata is the same as the actual metadata
			runningMetadata := svcVRFReconciler.getMetadata(testBGPInstance)
			req.Equal(tt.expectedAdverts, runningMetadata.vrfAdverts)

			// check NLRI of advertised Paths
			compareSimplePath(req, tt.expectedPaths, runningMetadata.vrfPaths)

			// check router's MAC of advertised Paths
			for _, vrfPaths := range runningMetadata.vrfPaths {
				for _, resourceAFPaths := range vrfPaths {
					for _, afPaths := range resourceAFPaths {
						for _, path := range afPaths {
							hasRoutersMac := false
							for _, pa := range path.PathAttributes {
								if pa.GetType() == bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES {
									for _, extComm := range pa.(*bgp.PathAttributeExtendedCommunities).Value {
										_, subType := extComm.GetTypes()
										if subType == bgp.EC_SUBTYPE_ROUTER_MAC {
											rm := extComm.(*bgp.RouterMacExtended)
											require.Equal(t, tt.vxlanDeviceMac, rm.Mac.String())
											hasRoutersMac = true
										}
									}
								}
							}
							require.True(t, hasRoutersMac, "Path should have Router's MAC extended community")
						}
					}
				}
			}
		})
	}
}
