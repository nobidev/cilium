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
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/annotation"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

func Test_ServiceHealthChecker(t *testing.T) {
	ingressV4 := "192.168.0.1"
	ingressV4Prefix := ingressV4 + "/32"
	ingressV4Path := types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix))
	ingressV6 := "fd00:192:168::1"
	ingressV6Prefix := ingressV6 + "/128"
	ingressV6Path := types.NewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix))

	svcSelector := slim_metav1.LabelSelector{MatchLabels: map[string]string{"advertise": "bgp"}}
	svcKey := resource.Key{Name: "test-svc", Namespace: "default"}
	ingressV4Frontend := loadbalancer.NewL3n4Addr(
		loadbalancer.TCP,
		cmtypes.MustParseAddrCluster(ingressV4),
		80,
		loadbalancer.ScopeExternal,
	)
	ingressV6Frontend := loadbalancer.NewL3n4Addr(
		loadbalancer.TCP,
		cmtypes.MustParseAddrCluster(ingressV6),
		80,
		loadbalancer.ScopeExternal,
	)
	fakeV4Frontend := loadbalancer.NewL3n4Addr(
		loadbalancer.TCP,
		cmtypes.MustParseAddrCluster("1.2.3.4"),
		80,
		loadbalancer.ScopeExternal,
	)

	instanceConfig := &v1.IsovalentBGPNodeInstance{
		Name:     "bgp-65001",
		LocalASN: ptr.To[int64](65001),
		Peers: []v1.IsovalentBGPNodePeer{
			{
				Name:        "peer-65001",
				PeerAddress: ptr.To[string]("10.10.10.1"),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: "peer-config",
				},
			},
		},
	}

	peerConfig := &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			CiliumBGPPeerConfigSpec: v2.CiliumBGPPeerConfigSpec{
				Families: []v2.CiliumBGPFamilyWithAdverts{
					{
						CiliumBGPFamily: v2.CiliumBGPFamily{
							Afi:  "ipv4",
							Safi: "unicast",
						},
						Advertisements: &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{
								"advertise": "bgp",
							},
						},
					},
					{
						CiliumBGPFamily: v2.CiliumBGPFamily{
							Afi:  "ipv6",
							Safi: "unicast",
						},
						Advertisements: &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{
								"advertise": "bgp",
							},
						},
					},
				},
			},
		},
	}

	svcAdvertisement := &v1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: "svc-advertisement",
			Labels: map[string]string{
				"advertise": "bgp",
			},
		},
		Spec: v1.IsovalentBGPAdvertisementSpec{
			Advertisements: []v1.BGPAdvertisement{
				{
					AdvertisementType: v1.BGPServiceAdvert,
					Service: &v1.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
					},
					Selector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"advertise": "bgp",
						},
					},
				},
			},
		},
	}

	peerID := PeerID{
		Name:    "peer-65001",
		Address: "10.10.10.1",
	}
	peerSvcAdvertisements := PeerAdvertisements{
		peerID: FamilyAdvertisements{
			{Afi: "ipv4", Safi: "unicast"}: svcAdvertisement.Spec.Advertisements,
			{Afi: "ipv6", Safi: "unicast"}: svcAdvertisement.Spec.Advertisements,
		},
	}

	svcRoutePolicy := &types.RoutePolicy{
		Name: PolicyName(instanceConfig.Peers[0].Name, "ipv4", v1.BGPServiceAdvert, fmt.Sprintf("%s-%s-LoadBalancerIP", svcKey.Name, svcKey.Namespace)),
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(ingressV4Prefix),
							PrefixLenMin: 32,
							PrefixLenMax: 32,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction: types.RoutePolicyActionAccept,
				},
			},
		},
	}

	svcRoutePolicyV6 := &types.RoutePolicy{
		Name: PolicyName(instanceConfig.Peers[0].Name, "ipv6", v1.BGPServiceAdvert, fmt.Sprintf("%s-%s-LoadBalancerIP", svcKey.Name, svcKey.Namespace)),
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(ingressV6Prefix),
							PrefixLenMin: 128,
							PrefixLenMax: 128,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction: types.RoutePolicyActionAccept,
				},
			},
		},
	}

	testSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:        svcKey.Name,
			Namespace:   svcKey.Namespace,
			Labels:      svcSelector.MatchLabels,
			Annotations: map[string]string{annotation.ServiceHealthProbeInterval: "5s"},
		},
		Spec: slim_corev1.ServiceSpec{
			Type: slim_corev1.ServiceTypeLoadBalancer,
			Ports: []slim_corev1.ServicePort{
				{
					Port: 80,
				},
			},
		},
		Status: slim_corev1.ServiceStatus{
			LoadBalancer: slim_corev1.LoadBalancerStatus{
				Ingress: []slim_corev1.LoadBalancerIngress{
					{
						IP: ingressV4,
					},
				},
			},
		},
	}
	testSvcNoHCAnnotation := testSvc.DeepCopy()
	testSvcNoHCAnnotation.Annotations = nil

	testSvcThreshold2 := testSvc.DeepCopy()
	testSvcThreshold2.Annotations = map[string]string{
		annotation.ServiceHealthProbeInterval:         "5s",
		annotation.ServiceHealthBGPAdvertiseThreshold: "2",
	}

	testSvcNoAdvertisement := testSvc.DeepCopy()
	testSvcNoAdvertisement.Annotations = map[string]string{
		annotation.ServiceNoAdvertisement: "true",
	}

	testSvcDualStack := testSvc.DeepCopy()
	testSvcDualStack.Status.LoadBalancer.Ingress = append(testSvcDualStack.Status.LoadBalancer.Ingress, slim_corev1.LoadBalancerIngress{IP: ingressV6})

	type backendUpdate struct {
		svcName        loadbalancer.ServiceName
		frontend       loadbalancer.L3n4Addr
		activeBackends []loadbalancer.BackendParams
	}

	var table = []struct {
		// name of the test case
		name string
		// advertisements to be upserted in the test step
		upsertedAdverts []*v1.IsovalentBGPAdvertisement
		// the services which will be upserted in the test step
		upsertedServices []*slim_corev1.Service
		// the services which will be deleted in the test step
		deletedServices []*slim_corev1.Service
		// a list of backend updates applied during the test step
		backendUpdates []backendUpdate
		// the expected metadata after the reconciliation
		expectedMetadata ServiceReconcilerMetadata
	}{
		{
			name:             "do not advertise new service with no health updates",
			upsertedAdverts:  []*v1.IsovalentBGPAdvertisement{svcAdvertisement},
			upsertedServices: []*slim_corev1.Service{testSvc},
			backendUpdates:   nil,
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {},
					},
				},
			},
		},
		{
			name: "advertise the service after healthy backend update",
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.BackendParams{{State: loadbalancer.BackendStateActive}}, // healthy
				},
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: ingressV4Path,
						},
					},
				},
			},
		},
		{
			name:             "advertise the service after multiple backend updates",
			upsertedServices: []*slim_corev1.Service{testSvc},
			backendUpdates: []backendUpdate{
				// first no healthy backends
				{
					svcName:        loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.BackendParams{{State: loadbalancer.BackendStateActive, Unhealthy: true}}, // unhealthy
				},
				// frontend not matching the service - unrelated
				{
					svcName:        loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.BackendParams{{State: loadbalancer.BackendStateActive}},
				},
				// finally with healthy backends
				{
					svcName:        loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.BackendParams{{State: loadbalancer.BackendStateActive}, {State: loadbalancer.BackendStateActive}}, // healthy
				},
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: ingressV4Path,
						},
					},
				},
			},
		},
		{
			name:             "do not advertise the service after unhealthy backend update",
			upsertedServices: []*slim_corev1.Service{testSvc},
			backendUpdates: []backendUpdate{
				// no active backends
				{
					svcName:        loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.BackendParams{}, // unhealthy
				},
				// frontend not matching the service - unrelated
				{
					svcName:        loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend:       fakeV4Frontend,
					activeBackends: []loadbalancer.BackendParams{{State: loadbalancer.BackendStateActive}, {State: loadbalancer.BackendStateActive}},
				},
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: nil,
					},
				},
			},
		},
		{
			name:             "advertise the service even after unhealthy backend update if health-checking is disabled",
			upsertedServices: []*slim_corev1.Service{testSvcNoHCAnnotation}, // missing health-check-probe-interval annotation
			backendUpdates: []backendUpdate{
				// frontend not matching the service - unrelated
				{
					svcName:        loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.BackendParams{}, // unhealthy
				},
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: ingressV4Path,
						},
					},
				},
			},
		},
		{
			name:             "do not advertise the service after unhealthy backend update",
			upsertedServices: []*slim_corev1.Service{testSvc},
			backendUpdates: []backendUpdate{
				// first with active backends
				{
					svcName:        loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.BackendParams{{State: loadbalancer.BackendStateActive}, {State: loadbalancer.BackendStateActive}},
				},
				// then no active backends
				{
					svcName:        loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.BackendParams{}, // unhealthy
				},
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: nil,
					},
				},
			},
		},
		{
			name:            "do not advertise deleted service even after healthy backend update",
			deletedServices: []*slim_corev1.Service{testSvc},
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.BackendParams{{State: loadbalancer.BackendStateActive}}, // healthy
				},
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies:  reconcilerv2.ResourceRoutePolicyMap{},
				ServicePaths:          reconcilerv2.ResourceAFPathsMap{},
			},
		},
		{
			name:             "advertise existing service with multiple frontend ports - all healthy",
			upsertedServices: []*slim_corev1.Service{testSvc},
			backendUpdates: []backendUpdate{
				{
					svcName: loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend: loadbalancer.NewL3n4Addr(
						loadbalancer.TCP,
						cmtypes.MustParseAddrCluster(ingressV4),
						80,
						loadbalancer.ScopeExternal,
					),
					activeBackends: []loadbalancer.BackendParams{{State: loadbalancer.BackendStateActive}}, // healthy
				},
				{
					svcName: loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend: loadbalancer.NewL3n4Addr(
						loadbalancer.TCP,
						cmtypes.MustParseAddrCluster(ingressV4),
						443,
						loadbalancer.ScopeExternal,
					),
					activeBackends: []loadbalancer.BackendParams{{State: loadbalancer.BackendStateActive}}, // healthy
				},
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: ingressV4Path,
						},
					},
				},
			},
		},
		{
			name: "withdraw the service with multiple frontend ports - 1 unhealthy port",
			backendUpdates: []backendUpdate{
				{
					svcName: loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend: loadbalancer.NewL3n4Addr(
						loadbalancer.TCP,
						cmtypes.MustParseAddrCluster(ingressV4),
						80,
						loadbalancer.ScopeExternal,
					),
					activeBackends: []loadbalancer.BackendParams{}, // unhealthy
				},
				{
					svcName: loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend: loadbalancer.NewL3n4Addr(
						loadbalancer.TCP,
						cmtypes.MustParseAddrCluster(ingressV4),
						443,
						loadbalancer.ScopeExternal,
					),
					activeBackends: []loadbalancer.BackendParams{{State: loadbalancer.BackendStateActive}}, // healthy
				},
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: nil,
					},
				},
			},
		},
		{
			name:             "advertise dual-stack service with multiple frontend IPs - all healthy",
			upsertedServices: []*slim_corev1.Service{testSvcDualStack},
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.BackendParams{{State: loadbalancer.BackendStateActive}}, // healthy
				},
				{
					svcName:        loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend:       ingressV6Frontend,
					activeBackends: []loadbalancer.BackendParams{{State: loadbalancer.BackendStateActive}}, // healthy
				},
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name:   svcRoutePolicy,
						svcRoutePolicyV6.Name: svcRoutePolicyV6,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: ingressV4Path,
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: ingressV6Path,
						},
					},
				},
			},
		},
		{
			name: "partially advertise dual-stack service with multiple frontend IPs - 1 unhealthy IP",
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.BackendParams{}, // unhealthy
				},
				{
					svcName:        loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend:       ingressV6Frontend,
					activeBackends: []loadbalancer.BackendParams{{State: loadbalancer.BackendStateActive}}, // healthy
				},
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name:   svcRoutePolicy,
						svcRoutePolicyV6.Name: svcRoutePolicyV6,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: nil,
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: ingressV6Path,
						},
					},
				},
			},
		},
		{
			name: "do not advertise dual-stack service with multiple frontend IPs - all unhealthy",
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.BackendParams{}, // unhealthy
				},
				{
					svcName:        loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend:       ingressV6Frontend,
					activeBackends: []loadbalancer.BackendParams{}, // unhealthy
				},
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name:   svcRoutePolicy,
						svcRoutePolicyV6.Name: svcRoutePolicyV6,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: nil,
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: nil,
					},
				},
			},
		},
		{
			name:             "advertise existing service after a backend update - non-default threshold, healthy",
			upsertedServices: []*slim_corev1.Service{testSvcThreshold2},
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.BackendParams{{State: loadbalancer.BackendStateActive}, {State: loadbalancer.BackendStateActive}}, // 2 backends - healthy
				},
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: ingressV4Path,
						},
					},
				},
			},
		},
		{
			name: "withdraw existing service after a backend update - non-default threshold, unhealthy",
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.BackendParams{{State: loadbalancer.BackendStateActive}}, // 1 backend - unhealthy
				},
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: nil,
					},
				},
			},
		},
		{
			name:             "do not advertise service with no-advertisement annotation",
			upsertedServices: []*slim_corev1.Service{testSvcNoAdvertisement},
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.NewServiceName(svcKey.Namespace, svcKey.Name),
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.BackendParams{{State: loadbalancer.BackendStateActive}}, // healthy
				},
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{},
			},
		},
	}

	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	var (
		testBGPInstance = instance.NewFakeBGPInstance()
		ceeBGPInstance  = &EnterpriseBGPInstance{
			Name:   testBGPInstance.Name,
			Router: testBGPInstance.Router,
		}
		mockPeerConfigStore = store.NewMockBGPCPResourceStore[*v1.IsovalentBGPPeerConfig]()
		mockAdvertStore     = store.NewMockBGPCPResourceStore[*v1.IsovalentBGPAdvertisement]()
		svcDiffstore        = store.NewFakeDiffStore[*slim_corev1.Service]()
		epDiffStore         = store.NewFakeDiffStore[*k8s.Endpoints]()
	)

	ceeParams := ServiceReconcilerIn{
		In:        cell.In{},
		Lifecycle: &cell.DefaultLifecycle{},
		Cfg: Config{
			SvcHealthCheckingEnabled:           true,
			MaintenanceGracefulShutdownEnabled: false,
			MaintenanceWithdrawTime:            0,
			RouterAdvertisementInterval:        defaultConfig.RouterAdvertisementInterval,
			EnableLegacySRv6Responder:          false,
		},
		BGPConfig:  config.Config{Enabled: true, StatusReportEnabled: false},
		Logger:     logger,
		Upgrader:   newUpgraderMock(instanceConfig),
		NSProvider: newMockNodeStatusProvider(),
		PeerAdvert: &IsovalentAdvertisement{
			logger:      logger,
			peerConfigs: mockPeerConfigStore,
			adverts:     mockAdvertStore,
		},
		SvcDiffStore: svcDiffstore,
		EPDiffStore:  epDiffStore,
		Signaler:     signaler.NewBGPCPSignaler(),
	}
	ceeReconciler := NewServiceReconciler(ceeParams).Reconciler.(*ServiceReconciler)

	// set peer advert state
	mockPeerConfigStore.Upsert(peerConfig)

	ceeReconciler.Init(testBGPInstance)
	defer ceeReconciler.Cleanup(testBGPInstance)

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			for _, advert := range tt.upsertedAdverts {
				mockAdvertStore.Upsert(advert)
			}
			for _, obj := range tt.upsertedServices {
				svcDiffstore.Upsert(obj)
			}
			for _, obj := range tt.deletedServices {
				svcDiffstore.Delete(obj)
			}

			// update active backends
			for _, upd := range tt.backendUpdates {
				fe := &loadbalancer.Frontend{
					FrontendParams: loadbalancer.FrontendParams{
						ServiceName: upd.svcName,
						Address:     upd.frontend,
						Type:        loadbalancer.SVCTypeLoadBalancer,
					},
					Backends: func(yield func(loadbalancer.BackendParams, uint64) bool) {
						for _, be := range upd.activeBackends {
							if !yield(be, 0) {
								break
							}
						}
					},
					ID:         0,
					RedirectTo: nil,
					Service: &loadbalancer.Service{
						Name: upd.svcName,
					},
				}
				ceeReconciler.frontendChanged(
					context.TODO(),
					statedb.Change[*loadbalancer.Frontend]{
						Object:   fe,
						Revision: 0,
						Deleted:  false,
					},
				)
			}

			err := ceeReconciler.Reconcile(context.Background(), reconcilerv2.ReconcileParams{
				BGPInstance: testBGPInstance,
				CiliumNode: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node1",
					},
				},
			})
			req.NoError(err)

			serviceMetadataEqual(req, tt.expectedMetadata, ceeReconciler.getMetadata(ceeBGPInstance))
		})
	}
}

var (
	redSvcKey            = resource.Key{Name: "red-svc", Namespace: "non-default"}
	redSvc2Key           = resource.Key{Name: "red-svc2", Namespace: "non-default"}
	redSvcSelector       = &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "red"}}
	mismatchSvcSelector  = &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}}
	aggregateV4Prefix24  = "192.168.0.0/24"
	ingressV4            = "192.168.0.1"
	ingressV4Prefix      = "192.168.0.1/32"
	externalV4           = "192.168.0.2"
	externalV4Prefix     = "192.168.0.2/32"
	clusterV4            = "192.168.0.3"
	clusterV4Prefix      = "192.168.0.3/32"
	aggregateV6Prefix120 = "2001:db8::/120"
	ingressV6            = "2001:db8::1"
	ingressV6Prefix      = "2001:db8::1/128"
	externalV6           = "2001:db8::2"
	externalV6Prefix     = "2001:db8::2/128"
	clusterV6            = "2001:db8::3"
	clusterV6Prefix      = "2001:db8::3/128"

	redLBSvc = &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      redSvcKey.Name,
			Namespace: redSvcKey.Namespace,
			Labels:    redSvcSelector.MatchLabels,
		},
		Spec: slim_corev1.ServiceSpec{
			Type: slim_corev1.ServiceTypeLoadBalancer,
		},
		Status: slim_corev1.ServiceStatus{
			LoadBalancer: slim_corev1.LoadBalancerStatus{
				Ingress: []slim_corev1.LoadBalancerIngress{
					{
						IP: ingressV4,
					},
					{
						IP: ingressV6,
					},
				},
			},
		},
	}
	redLBSvcWithETP = func(eTP slim_corev1.ServiceExternalTrafficPolicy) *slim_corev1.Service {
		cp := redLBSvc.DeepCopy()
		cp.Spec.ExternalTrafficPolicy = eTP
		return cp
	}
	redLBSvc2 = func() *slim_corev1.Service {
		cp := redLBSvc.DeepCopy()
		cp.Name = redLBSvc.Name + "2"
		return cp
	}

	redPeer65001v4LBRPName = PolicyName("red-peer-65001", "ipv4", v1.BGPServiceAdvert, "red-svc-non-default-LoadBalancerIP")
	redPeer65001v4LBRP     = &types.RoutePolicy{
		Name: redPeer65001v4LBRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(ingressV4Prefix),
							PrefixLenMin: 32,
							PrefixLenMax: 32,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}

	redPeer65001Svc2v4LBRPName = PolicyName("red-peer-65001", "ipv4", v1.BGPServiceAdvert, "red-svc2-non-default-LoadBalancerIP")
	redPeer65001Svc2v4LBRP     = func() *types.RoutePolicy {
		return &types.RoutePolicy{
			Name:       redPeer65001Svc2v4LBRPName,
			Type:       types.RoutePolicyTypeExport,
			Statements: redPeer65001v4LBRP.Statements,
		}
	}

	redPeer65001v4LBRPWith24PrefixLen = &types.RoutePolicy{
		Name: redPeer65001v4LBRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(aggregateV4Prefix24),
							PrefixLenMin: 24, // It's hardcoded to 24 for tests
							PrefixLenMax: 24,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}
	redPeer65001v4LBRPMultiPaths = &types.RoutePolicy{
		Name: redPeer65001v4LBRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			// Sorted from longest to shortest prefix length
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(ingressV4Prefix),
							PrefixLenMin: 32,
							PrefixLenMax: 32,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(aggregateV4Prefix24),
							PrefixLenMin: 24, // It's hardcoded to 24 for tests
							PrefixLenMax: 24,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}

	redPeer65001v6LBRPName = PolicyName("red-peer-65001", "ipv6", v1.BGPServiceAdvert, "red-svc-non-default-LoadBalancerIP")
	redPeer65001v6LBRP     = &types.RoutePolicy{
		Name: redPeer65001v6LBRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(ingressV6Prefix),
							PrefixLenMin: 128,
							PrefixLenMax: 128,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}
	redPeer65001v6LBRPWith120PrefixLen = &types.RoutePolicy{
		Name: redPeer65001v6LBRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(aggregateV6Prefix120),
							PrefixLenMin: 120,
							PrefixLenMax: 120,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}
	redPeer65001v6LBRPMultiPaths = &types.RoutePolicy{
		Name: redPeer65001v6LBRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			// Sorted from longest to shortest prefix length
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(ingressV6Prefix),
							PrefixLenMin: 128,
							PrefixLenMax: 128,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(aggregateV6Prefix120),
							PrefixLenMin: 120,
							PrefixLenMax: 120,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}
	redPeer65001Svc2v6LBRPName = PolicyName("red-peer-65001", "ipv6", v1.BGPServiceAdvert, "red-svc2-non-default-LoadBalancerIP")
	redPeer65001Svc2v6LBRP     = func() *types.RoutePolicy {
		return &types.RoutePolicy{
			Name:       redPeer65001Svc2v6LBRPName,
			Type:       types.RoutePolicyTypeExport,
			Statements: redPeer65001v6LBRP.Statements,
		}
	}

	redExternalSvc = &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      redSvcKey.Name,
			Namespace: redSvcKey.Namespace,
			Labels:    redSvcSelector.MatchLabels,
		},
		Spec: slim_corev1.ServiceSpec{
			Type: slim_corev1.ServiceTypeClusterIP,
			ExternalIPs: []string{
				externalV4,
				externalV6,
			},
		},
	}

	redExternalSvcWithETP = func(eTP slim_corev1.ServiceExternalTrafficPolicy) *slim_corev1.Service {
		cp := redExternalSvc.DeepCopy()
		cp.Spec.ExternalTrafficPolicy = eTP
		return cp
	}

	redPeer65001v4ExtRPName = PolicyName("red-peer-65001", "ipv4", v1.BGPServiceAdvert, "red-svc-non-default-ExternalIP")
	redPeer65001v4ExtRP     = &types.RoutePolicy{
		Name: redPeer65001v4ExtRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(externalV4Prefix),
							PrefixLenMin: 32,
							PrefixLenMax: 32,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}
	redPeer65001v4ExtRPWithPrefixAgg = &types.RoutePolicy{
		Name: redPeer65001v4ExtRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(aggregateV4Prefix24),
							PrefixLenMin: 24,
							PrefixLenMax: 24,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}
	redPeer65001v4ExtRPMultiPaths = &types.RoutePolicy{
		Name: redPeer65001v4ExtRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			// Sorted from longest to shortest prefix length
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(externalV4Prefix),
							PrefixLenMin: 32,
							PrefixLenMax: 32,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(aggregateV4Prefix24),
							PrefixLenMin: 24, // It's hardcoded to 24 for tests
							PrefixLenMax: 24,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}

	redPeer65001v6ExtRPName = PolicyName("red-peer-65001", "ipv6", v1.BGPServiceAdvert, "red-svc-non-default-ExternalIP")
	redPeer65001v6ExtRP     = &types.RoutePolicy{
		Name: redPeer65001v6ExtRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(externalV6Prefix),
							PrefixLenMin: 128,
							PrefixLenMax: 128,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}
	redPeer65001v6ExtRPWithPrefixAgg = &types.RoutePolicy{
		Name: redPeer65001v6ExtRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(aggregateV6Prefix120),
							PrefixLenMin: 120,
							PrefixLenMax: 120,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}
	redPeer65001v6ExtRPMultiPaths = &types.RoutePolicy{
		Name: redPeer65001v6ExtRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			// Sorted from longest to shortest prefix length
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(externalV6Prefix),
							PrefixLenMin: 128,
							PrefixLenMax: 128,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(aggregateV6Prefix120),
							PrefixLenMin: 120,
							PrefixLenMax: 120,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}

	redClusterSvc = &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      redSvcKey.Name,
			Namespace: redSvcKey.Namespace,
			Labels:    redSvcSelector.MatchLabels,
		},
		Spec: slim_corev1.ServiceSpec{
			Type:      slim_corev1.ServiceTypeClusterIP,
			ClusterIP: clusterV4,
			ClusterIPs: []string{
				clusterV4,
				clusterV6,
			},
		},
	}

	redClusterSvcWithITP = func(iTP slim_corev1.ServiceInternalTrafficPolicy) *slim_corev1.Service {
		cp := redClusterSvc.DeepCopy()
		cp.Spec.InternalTrafficPolicy = &iTP
		return cp
	}

	redPeer65001v4ClusterRPName = PolicyName("red-peer-65001", "ipv4", v1.BGPServiceAdvert, "red-svc-non-default-ClusterIP")
	redPeer65001v4ClusterRP     = &types.RoutePolicy{
		Name: redPeer65001v4ClusterRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(clusterV4Prefix),
							PrefixLenMin: 32,
							PrefixLenMax: 32,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}
	redPeer65001v4ClusterRPWithPrefixAgg = &types.RoutePolicy{
		Name: redPeer65001v4ClusterRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(aggregateV4Prefix24),
							PrefixLenMin: 24,
							PrefixLenMax: 24,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}
	redPeer65001v4ClusterRPMultiPaths = &types.RoutePolicy{
		Name: redPeer65001v4ClusterRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			// Sorted from longest to shortest prefix length
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(clusterV4Prefix),
							PrefixLenMin: 32,
							PrefixLenMax: 32,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(aggregateV4Prefix24),
							PrefixLenMin: 24, // It's hardcoded to 24 for tests
							PrefixLenMax: 24,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}

	redPeer65001v6ClusterRPName = PolicyName("red-peer-65001", "ipv6", v1.BGPServiceAdvert, "red-svc-non-default-ClusterIP")
	redPeer65001v6ClusterRP     = &types.RoutePolicy{
		Name: redPeer65001v6ClusterRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(clusterV6Prefix),
							PrefixLenMin: 128,
							PrefixLenMax: 128,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}
	redPeer65001v6ClusterRPWithPrefixAgg = &types.RoutePolicy{
		Name: redPeer65001v6ClusterRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(aggregateV6Prefix120),
							PrefixLenMin: 120,
							PrefixLenMax: 120,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}
	redPeer65001v6ClusterRPMultiPaths = &types.RoutePolicy{
		Name: redPeer65001v6ClusterRPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			// Sorted from longest to shortest prefix length
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(clusterV6Prefix),
							PrefixLenMin: 128,
							PrefixLenMax: 128,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(aggregateV6Prefix120),
							PrefixLenMin: 120,
							PrefixLenMax: 120,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65535:65281"},
				},
			},
		},
	}

	redExternalAndClusterSvc = &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      redSvcKey.Name,
			Namespace: redSvcKey.Namespace,
			Labels:    redSvcSelector.MatchLabels,
		},
		Spec: slim_corev1.ServiceSpec{
			Type:      slim_corev1.ServiceTypeClusterIP,
			ClusterIP: clusterV4,
			ClusterIPs: []string{
				clusterV4,
				clusterV6,
			},
			ExternalIPs: []string{
				externalV4,
				externalV6,
			},
		},
	}

	svcWithITP = func(svc *slim_corev1.Service, iTP slim_corev1.ServiceInternalTrafficPolicy) *slim_corev1.Service {
		cp := svc.DeepCopy()
		cp.Spec.InternalTrafficPolicy = &iTP
		return cp
	}

	svcWithETP = func(svc *slim_corev1.Service, eTP slim_corev1.ServiceExternalTrafficPolicy) *slim_corev1.Service {
		cp := svc.DeepCopy()
		cp.Spec.ExternalTrafficPolicy = eTP
		return cp
	}

	redSvcAdvert = &v1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: "red-advertisement",
			Labels: map[string]string{
				"advertise": "red_bgp",
			},
		},
	}

	redSvcAdvertWithAdvertisements = func(adverts ...v1.BGPAdvertisement) *v1.IsovalentBGPAdvertisement {
		cp := redSvcAdvert.DeepCopy()
		cp.Spec.Advertisements = adverts
		return cp
	}

	redV6SvcAdvert = &v1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: "red-v6-advertisement",
			Labels: map[string]string{
				"advertise": "red_bgp_v6",
			},
		},
	}

	redV6SvcAdvertWithAdvertisements = func(adverts ...v1.BGPAdvertisement) *v1.IsovalentBGPAdvertisement {
		cp := redV6SvcAdvert.DeepCopy()
		cp.Spec.Advertisements = adverts
		return cp
	}

	lbSvcAdvert = v1.BGPAdvertisement{
		AdvertisementType: v1.BGPServiceAdvert,
		Service: &v1.BGPServiceOptions{
			Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
		},
		Attributes: &v2.BGPAttributes{
			Communities: &v2.BGPCommunities{
				Standard:  []v2.BGPStandardCommunity{"65535:65281"},
				WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
			},
		},
	}
	lbSvcAdvertWithSelector = func(selector *slim_metav1.LabelSelector) v1.BGPAdvertisement {
		cp := lbSvcAdvert.DeepCopy()
		cp.Selector = selector
		return *cp
	}
	lbSvcAdvertWithSelectorAndPrefixLen = func(selector *slim_metav1.LabelSelector, prefixLen int32) v1.BGPAdvertisement {
		cp := lbSvcAdvert.DeepCopy()
		cp.Selector = selector
		if prefixLen < 32 {
			cp.Service.AggregationLengthIPv4 = ptr.To[int32](prefixLen)
		} else {
			cp.Service.AggregationLengthIPv6 = ptr.To[int32](prefixLen)
		}
		return *cp
	}

	externalSvcAdvert = v1.BGPAdvertisement{
		AdvertisementType: v1.BGPServiceAdvert,
		Service: &v1.BGPServiceOptions{
			Addresses: []v2.BGPServiceAddressType{v2.BGPExternalIPAddr},
		},
		Attributes: &v2.BGPAttributes{
			Communities: &v2.BGPCommunities{
				Standard:  []v2.BGPStandardCommunity{"65535:65281"},
				WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
			},
		},
	}

	externalSvcAdvertWithSelector = func(selector *slim_metav1.LabelSelector) v1.BGPAdvertisement {
		cp := externalSvcAdvert.DeepCopy()
		cp.Selector = selector
		return *cp
	}
	exSvcAdvertWithSelectorAndPrefixLen = func(selector *slim_metav1.LabelSelector, prefixLen int32) v1.BGPAdvertisement {
		cp := externalSvcAdvert.DeepCopy()
		cp.Selector = selector
		if prefixLen < 32 {
			cp.Service.AggregationLengthIPv4 = ptr.To[int32](prefixLen)
		} else {
			cp.Service.AggregationLengthIPv6 = ptr.To[int32](prefixLen)
		}
		return *cp
	}

	clusterIPSvcAdvert = v1.BGPAdvertisement{
		AdvertisementType: v1.BGPServiceAdvert,
		Service: &v1.BGPServiceOptions{
			Addresses: []v2.BGPServiceAddressType{v2.BGPClusterIPAddr},
		},
		Attributes: &v2.BGPAttributes{
			Communities: &v2.BGPCommunities{
				Standard:  []v2.BGPStandardCommunity{"65535:65281"},
				WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
			},
		},
	}

	clusterIPSvcAdvertWithSelector = func(selector *slim_metav1.LabelSelector) v1.BGPAdvertisement {
		cp := clusterIPSvcAdvert.DeepCopy()
		cp.Selector = selector
		return *cp
	}
	clusterIPSvcAdvertWithSelectorAndPrefixLen = func(selector *slim_metav1.LabelSelector, prefixLen int32) v1.BGPAdvertisement {
		cp := clusterIPSvcAdvert.DeepCopy()
		cp.Selector = selector
		if prefixLen < 32 {
			cp.Service.AggregationLengthIPv4 = ptr.To[int32](prefixLen)
		} else {
			cp.Service.AggregationLengthIPv6 = ptr.To[int32](prefixLen)
		}
		return *cp
	}

	// red peer config
	redPeerConfig = &v1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config-red",
		},
		Spec: v1.IsovalentBGPPeerConfigSpec{
			CiliumBGPPeerConfigSpec: v2.CiliumBGPPeerConfigSpec{
				Families: []v2.CiliumBGPFamilyWithAdverts{
					{
						CiliumBGPFamily: v2.CiliumBGPFamily{
							Afi:  "ipv4",
							Safi: "unicast",
						},
						Advertisements: &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{
								"advertise": "red_bgp",
							},
						},
					},
					{
						CiliumBGPFamily: v2.CiliumBGPFamily{
							Afi:  "ipv6",
							Safi: "unicast",
						},
						Advertisements: &slim_metav1.LabelSelector{
							MatchLabels: map[string]string{
								"advertise": "red_bgp_v6",
							},
						},
					},
				},
			},
		},
	}

	testBGPInstanceConfig = &v1.IsovalentBGPNodeInstance{
		Name:     "bgp-65001",
		LocalASN: ptr.To[int64](65001),
		Peers: []v1.IsovalentBGPNodePeer{
			{
				Name:        "red-peer-65001",
				PeerAddress: ptr.To[string]("10.10.10.1"),
				PeerConfigRef: &v1.PeerConfigReference{
					Name: "peer-config-red",
				},
			},
		},
	}

	testPeerID = PeerID{
		Name:    "red-peer-65001",
		Address: "10.10.10.1",
	}

	eps1Local = &k8s.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "svc-1",
			Namespace: "non-default",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceName:       loadbalancer.NewServiceName(redSvcKey.Namespace, redSvcKey.Name),
			EndpointSliceName: "svc-1",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("10.0.0.1"): {
				NodeName: "node1",
			},
			cmtypes.MustParseAddrCluster("2001:db8:1000::1"): {
				NodeName: "node1",
			},
		},
	}

	eps1LocalTerminating = &k8s.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "svc-1",
			Namespace: "non-default",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceName:       loadbalancer.NewServiceName(redSvcKey.Namespace, redSvcKey.Name),
			EndpointSliceName: "svc-1",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("10.0.0.1"): {
				NodeName:   "node1",
				Conditions: k8s.BackendConditionTerminating,
			},
			cmtypes.MustParseAddrCluster("2001:db8:1000::1"): {
				NodeName:   "node1",
				Conditions: k8s.BackendConditionTerminating,
			},
		},
	}

	eps1Remote = &k8s.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "svc-1",
			Namespace: "default",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceName:       loadbalancer.NewServiceName(redSvcKey.Namespace, redSvcKey.Name),
			EndpointSliceName: "svc-1",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("10.0.0.2"): {
				NodeName: "node2",
			},
			cmtypes.MustParseAddrCluster("2001:db8:1000::2"): {
				NodeName: "node2",
			},
		},
	}

	eps1Mixed = &k8s.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "svc-1",
			Namespace: "default",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceName:       loadbalancer.NewServiceName(redSvcKey.Namespace, redSvcKey.Name),
			EndpointSliceName: "svc-1",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("10.0.0.1"): {
				NodeName: "node1",
			},
			cmtypes.MustParseAddrCluster("10.0.0.2"): {
				NodeName: "node2",
			},
			cmtypes.MustParseAddrCluster("2001:db8:1000::1"): {
				NodeName: "node1",
			},
			cmtypes.MustParseAddrCluster("2001:db8:1000::2"): {
				NodeName: "node2",
			},
		},
	}
)

// Test_ServiceLBReconciler tests reconciliation of service of type load-balancer
func Test_ServiceLBReconciler(t *testing.T) {
	tests := []struct {
		name             string
		peerConfigs      []*v1.IsovalentBGPPeerConfig
		advertisements   []*v1.IsovalentBGPAdvertisement
		services         []*slim_corev1.Service
		endpoints        []*k8s.Endpoints
		expectedMetadata ServiceReconcilerMetadata
	}{
		{
			name:           "Service (LB) with advertisement( empty )",
			peerConfigs:    []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:       []*slim_corev1.Service{redLBSvc},
			advertisements: nil,
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconcilerv2.ResourceAFPathsMap{},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: nil,
						{Afi: "ipv6", Safi: "unicast"}: nil,
					},
				},
			},
		},
		{
			name:        "Service (LB) with advertisement(LB) - mismatch labels",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redLBSvc},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(mismatchSvcSelector)),
				redV6SvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(mismatchSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconcilerv2.ResourceAFPathsMap{},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(mismatchSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(mismatchSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (LB) with advertisement(LB) - matching labels (eTP=cluster)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redLBSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyCluster)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (LB) with advertisement(LB) - matching labels (eTP=local, ep on node)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redLBSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			endpoints:   []*k8s.Endpoints{eps1Local},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (LB) with advertisement(LB) - matching labels (eTP=local, mixed ep)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redLBSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			endpoints:   []*k8s.Endpoints{eps1Mixed},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (LB) with advertisement(LB) - matching labels (eTP=local, ep on remote)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redLBSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			endpoints:   []*k8s.Endpoints{eps1Remote},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconcilerv2.ResourceAFPathsMap{},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (LB) with advertisement(LB) - matching labels (eTP=local, backends are terminating)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redLBSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			endpoints:   []*k8s.Endpoints{eps1LocalTerminating},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconcilerv2.ResourceAFPathsMap{},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (LB) with advertisement(LB) - prefix aggregation (eTP=Cluster, iTP=Local)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{svcWithITP(redLBSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyCluster), slim_corev1.ServiceInternalTrafficPolicyLocal)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24)),
				redV6SvcAdvertWithAdvertisements(lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							aggregateV4Prefix24: types.NewPathForPrefix(netip.MustParsePrefix(aggregateV4Prefix24)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							aggregateV6Prefix120: types.NewPathForPrefix(netip.MustParsePrefix(aggregateV6Prefix120)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRPWith24PrefixLen,
						redPeer65001v6LBRPName: redPeer65001v6LBRPWith120PrefixLen,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120),
						},
					},
				},
			},
		},
		{
			name:        "Service (LB) with advertisement(LB) - eTP=Local, iTP=Cluster - no prefix aggregation",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{svcWithITP(redLBSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal), slim_corev1.ServiceInternalTrafficPolicyCluster)},
			endpoints:   []*k8s.Endpoints{eps1Local},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24)),
				redV6SvcAdvertWithAdvertisements(lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)), // /32 advertisement
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)), // /128 advertisement
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP, // policy is also created for /32 advertisement
						redPeer65001v6LBRPName: redPeer65001v6LBRP, // policy is also created for /128 advertisement
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120),
						},
					},
				},
			},
		},
		{
			name:        "Service (LB) with advertisement(LB) - prefix aggregation (eTP=Cluster), aggregate and full match advertisement",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redLBSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyCluster)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24), lbSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120), lbSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							aggregateV4Prefix24: types.NewPathForPrefix(netip.MustParsePrefix(aggregateV4Prefix24)),
							ingressV4Prefix:     types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							aggregateV6Prefix120: types.NewPathForPrefix(netip.MustParsePrefix(aggregateV6Prefix120)),
							ingressV6Prefix:      types.NewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRPMultiPaths,
						redPeer65001v6LBRPName: redPeer65001v6LBRPMultiPaths,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24),
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120),
							lbSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

			var (
				testBGPInstance = instance.NewFakeBGPInstance()
				ceeBGPInstance  = &EnterpriseBGPInstance{
					Name:   testBGPInstance.Name,
					Router: testBGPInstance.Router,
				}
				mockPeerConfigStore = store.NewMockBGPCPResourceStore[*v1.IsovalentBGPPeerConfig]()
				mockAdvertStore     = store.NewMockBGPCPResourceStore[*v1.IsovalentBGPAdvertisement]()
				svcDiffstore        = store.NewFakeDiffStore[*slim_corev1.Service]()
				epDiffStore         = store.NewFakeDiffStore[*k8s.Endpoints]()
			)

			ceeParams := ServiceReconcilerIn{
				In:         cell.In{},
				Lifecycle:  &cell.DefaultLifecycle{},
				Cfg:        defaultConfig,
				BGPConfig:  config.Config{Enabled: true, StatusReportEnabled: false},
				Logger:     logger,
				Upgrader:   newUpgraderMock(testBGPInstanceConfig),
				NSProvider: newMockNodeStatusProvider(),
				PeerAdvert: &IsovalentAdvertisement{
					logger:      logger,
					peerConfigs: mockPeerConfigStore,
					adverts:     mockAdvertStore,
				},
				SvcDiffStore: svcDiffstore,
				EPDiffStore:  epDiffStore,
				Signaler:     signaler.NewBGPCPSignaler(),
			}

			ceeReconciler := NewServiceReconciler(ceeParams).Reconciler.(*ServiceReconciler)

			ceeReconciler.Init(testBGPInstance)
			defer ceeReconciler.Cleanup(testBGPInstance)

			for _, peerConfig := range tt.peerConfigs {
				mockPeerConfigStore.Upsert(peerConfig)
			}

			for _, svc := range tt.services {
				svcDiffstore.Upsert(svc)
			}

			for _, ep := range tt.endpoints {
				epDiffStore.Upsert(ep)
			}

			for _, advert := range tt.advertisements {
				mockAdvertStore.Upsert(advert)
			}

			// reconcile twice to validate idempotency
			for i := 0; i < 2; i++ {
				err := ceeReconciler.Reconcile(context.Background(), reconcilerv2.ReconcileParams{
					BGPInstance: testBGPInstance,
					CiliumNode: &v2.CiliumNode{
						ObjectMeta: metav1.ObjectMeta{
							Name: "node1",
						},
					},
				})
				req.NoError(err)
			}

			// validate new metadata
			serviceMetadataEqual(req, tt.expectedMetadata, ceeReconciler.getMetadata(ceeBGPInstance))

			// validate that advertised paths match expected metadata
			advertisedPrefixesMatch(req, testBGPInstance, tt.expectedMetadata.ServicePaths)
		})
	}
}

// Test_ServiceExternalIPReconciler tests reconciliation of cluster service with external IP
func Test_ServiceExternalIPReconciler(t *testing.T) {
	tests := []struct {
		name             string
		peerConfigs      []*v1.IsovalentBGPPeerConfig
		advertisements   []*v1.IsovalentBGPAdvertisement
		services         []*slim_corev1.Service
		endpoints        []*k8s.Endpoints
		expectedMetadata ServiceReconcilerMetadata
	}{
		{
			name:           "Service (External) with advertisement( empty )",
			peerConfigs:    []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:       []*slim_corev1.Service{redExternalSvc},
			advertisements: nil,
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconcilerv2.ResourceAFPathsMap{},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: nil,
						{Afi: "ipv6", Safi: "unicast"}: nil,
					},
				},
			},
		},
		{
			name:        "Service (External) with advertisement(External) - mismatch labels",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redExternalSvc},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(mismatchSvcSelector)),
				redV6SvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(mismatchSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconcilerv2.ResourceAFPathsMap{},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							externalSvcAdvertWithSelector(mismatchSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							externalSvcAdvertWithSelector(mismatchSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (External) with advertisement(External) - matching labels (eTP=cluster)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redExternalSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyCluster)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							externalV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							externalV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4ExtRPName: redPeer65001v4ExtRP,
						redPeer65001v6ExtRPName: redPeer65001v6ExtRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (External) with advertisement(External) - matching labels (eTP=local, ep on node)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redExternalSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			endpoints:   []*k8s.Endpoints{eps1Local},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							externalV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							externalV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4ExtRPName: redPeer65001v4ExtRP,
						redPeer65001v6ExtRPName: redPeer65001v6ExtRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (External) with advertisement(External) - matching labels (eTP=local, mixed ep)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redExternalSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			endpoints:   []*k8s.Endpoints{eps1Mixed},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							externalV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							externalV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4ExtRPName: redPeer65001v4ExtRP,
						redPeer65001v6ExtRPName: redPeer65001v6ExtRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (External) with advertisement(External) - matching labels (eTP=local, ep on remote)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redExternalSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal)},
			endpoints:   []*k8s.Endpoints{eps1Remote},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(externalSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconcilerv2.ResourceAFPathsMap{},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							externalSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (External) with prefix aggregation - eTP=Cluster, iTP=Local",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{svcWithITP(redExternalSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyCluster), slim_corev1.ServiceInternalTrafficPolicyLocal)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24)),
				redV6SvcAdvertWithAdvertisements(exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							aggregateV4Prefix24: types.NewPathForPrefix(netip.MustParsePrefix(aggregateV4Prefix24)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							aggregateV6Prefix120: types.NewPathForPrefix(netip.MustParsePrefix(aggregateV6Prefix120)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4ExtRPName: redPeer65001v4ExtRPWithPrefixAgg,
						redPeer65001v6ExtRPName: redPeer65001v6ExtRPWithPrefixAgg,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120),
						},
					},
				},
			},
		},
		{
			name:        "Service (External) with advertisement(External) - eTP=Local, iTP=Cluster - no prefix aggregation",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{svcWithITP(redExternalSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyLocal), slim_corev1.ServiceInternalTrafficPolicyCluster)},
			endpoints:   []*k8s.Endpoints{eps1Local},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24)),
				redV6SvcAdvertWithAdvertisements(exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							externalV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)), // /32 advertisement
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							externalV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)), // /128 advertisement
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4ExtRPName: redPeer65001v4ExtRP, // /32 policy
						redPeer65001v6ExtRPName: redPeer65001v6ExtRP, // /128 policy
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120),
						},
					},
				},
			},
		},
		{
			name:        "Service (External) with advertisement(External) - prefix aggregation (eTP=Cluster), aggregate and full match advertisement",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redExternalSvcWithETP(slim_corev1.ServiceExternalTrafficPolicyCluster)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24), externalSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120), externalSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							aggregateV4Prefix24: types.NewPathForPrefix(netip.MustParsePrefix(aggregateV4Prefix24)),
							externalV4Prefix:    types.NewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							aggregateV6Prefix120: types.NewPathForPrefix(netip.MustParsePrefix(aggregateV6Prefix120)),
							externalV6Prefix:     types.NewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4ExtRPName: redPeer65001v4ExtRPMultiPaths,
						redPeer65001v6ExtRPName: redPeer65001v6ExtRPMultiPaths,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24),
							externalSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							exSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120),
							externalSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

			var (
				testBGPInstance = instance.NewFakeBGPInstance()
				ceeBGPInstance  = &EnterpriseBGPInstance{
					Name:   testBGPInstance.Name,
					Router: testBGPInstance.Router,
				}
				mockPeerConfigStore = store.NewMockBGPCPResourceStore[*v1.IsovalentBGPPeerConfig]()
				mockAdvertStore     = store.NewMockBGPCPResourceStore[*v1.IsovalentBGPAdvertisement]()
				svcDiffstore        = store.NewFakeDiffStore[*slim_corev1.Service]()
				epDiffStore         = store.NewFakeDiffStore[*k8s.Endpoints]()
			)

			ceeParams := ServiceReconcilerIn{
				In:         cell.In{},
				Lifecycle:  &cell.DefaultLifecycle{},
				Cfg:        defaultConfig,
				BGPConfig:  config.Config{Enabled: true, StatusReportEnabled: false},
				Logger:     logger,
				Upgrader:   newUpgraderMock(testBGPInstanceConfig),
				NSProvider: newMockNodeStatusProvider(),
				PeerAdvert: &IsovalentAdvertisement{
					logger:      logger,
					peerConfigs: mockPeerConfigStore,
					adverts:     mockAdvertStore,
				},
				SvcDiffStore: svcDiffstore,
				EPDiffStore:  epDiffStore,
				Signaler:     signaler.NewBGPCPSignaler(),
			}

			ceeReconciler := NewServiceReconciler(ceeParams).Reconciler.(*ServiceReconciler)

			ceeReconciler.Init(testBGPInstance)
			defer ceeReconciler.Cleanup(testBGPInstance)

			for _, peerConfig := range tt.peerConfigs {
				mockPeerConfigStore.Upsert(peerConfig)
			}

			for _, svc := range tt.services {
				svcDiffstore.Upsert(svc)
			}

			for _, ep := range tt.endpoints {
				epDiffStore.Upsert(ep)
			}

			for _, advert := range tt.advertisements {
				mockAdvertStore.Upsert(advert)
			}

			// reconcile twice to validate idempotency
			for i := 0; i < 2; i++ {
				err := ceeReconciler.Reconcile(context.Background(), reconcilerv2.ReconcileParams{
					BGPInstance: testBGPInstance,
					CiliumNode: &v2.CiliumNode{
						ObjectMeta: metav1.ObjectMeta{
							Name: "node1",
						},
					},
				})
				req.NoError(err)
			}

			// validate new metadata
			serviceMetadataEqual(req, tt.expectedMetadata, ceeReconciler.getMetadata(ceeBGPInstance))

			// validate that advertised paths match expected metadata
			advertisedPrefixesMatch(req, testBGPInstance, tt.expectedMetadata.ServicePaths)
		})
	}
}

// Test_ServiceClusterIPReconciler tests reconciliation of cluster service
func Test_ServiceClusterIPReconciler(t *testing.T) {
	tests := []struct {
		name             string
		peerConfigs      []*v1.IsovalentBGPPeerConfig
		advertisements   []*v1.IsovalentBGPAdvertisement
		services         []*slim_corev1.Service
		endpoints        []*k8s.Endpoints
		expectedMetadata ServiceReconcilerMetadata
	}{
		{
			name:           "Service (Cluster) with advertisement( empty )",
			peerConfigs:    []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:       []*slim_corev1.Service{redClusterSvc},
			advertisements: nil,
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconcilerv2.ResourceAFPathsMap{},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: nil,
						{Afi: "ipv6", Safi: "unicast"}: nil,
					},
				},
			},
		},
		{
			name:        "Service (Cluster) with advertisement(Cluster) - mismatch labels",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redClusterSvc},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(mismatchSvcSelector)),
				redV6SvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(mismatchSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconcilerv2.ResourceAFPathsMap{},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(mismatchSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(mismatchSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (Cluster) with advertisement(Cluster) - matching labels (iTP=cluster)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redClusterSvcWithITP(slim_corev1.ServiceInternalTrafficPolicyCluster)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRP,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (Cluster) with advertisement(Cluster) - matching labels (eTP=local, ep on node)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redClusterSvcWithITP(slim_corev1.ServiceInternalTrafficPolicyLocal)},
			endpoints:   []*k8s.Endpoints{eps1Local},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRP,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (Cluster) with advertisement(Cluster) - matching labels (eTP=local, mixed ep)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redClusterSvcWithITP(slim_corev1.ServiceInternalTrafficPolicyLocal)},
			endpoints:   []*k8s.Endpoints{eps1Mixed},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRP,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (Cluster) with advertisement(Cluster) - matching labels (eTP=local, ep on remote)",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redClusterSvcWithITP(slim_corev1.ServiceInternalTrafficPolicyLocal)},
			endpoints:   []*k8s.Endpoints{eps1Remote},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconcilerv2.ResourceAFPathsMap{},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
		{
			name:        "Service (Cluster) with prefix aggregation - eTP=Cluster",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redClusterSvcWithITP(slim_corev1.ServiceInternalTrafficPolicyCluster)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24)),
				redV6SvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							aggregateV4Prefix24: types.NewPathForPrefix(netip.MustParsePrefix(aggregateV4Prefix24)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							aggregateV6Prefix120: types.NewPathForPrefix(netip.MustParsePrefix(aggregateV6Prefix120)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRPWithPrefixAgg,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRPWithPrefixAgg,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120),
						},
					},
				},
			},
		},
		{
			name:        "Service (Cluster) with advertisement(Cluster) - iTP=Local - no prefix aggregation",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redClusterSvcWithITP(slim_corev1.ServiceInternalTrafficPolicyLocal)},
			endpoints:   []*k8s.Endpoints{eps1Local},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24)),
				redV6SvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)), // /32 advertisement
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)), // /128 advertisement
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRP, // /32 policy
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRP, // /128 policy
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120),
						},
					},
				},
			},
		},
		{
			name:        "Service (Cluster) with advertisement(Cluster) - prefix aggregation (iTP=Cluster), aggregate and full match advertisement",
			peerConfigs: []*v1.IsovalentBGPPeerConfig{redPeerConfig},
			services:    []*slim_corev1.Service{redClusterSvcWithITP(slim_corev1.ServiceInternalTrafficPolicyCluster)},
			advertisements: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24), clusterIPSvcAdvertWithSelector(redSvcSelector)),
				redV6SvcAdvertWithAdvertisements(clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120), clusterIPSvcAdvertWithSelector(redSvcSelector)),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							aggregateV4Prefix24: types.NewPathForPrefix(netip.MustParsePrefix(aggregateV4Prefix24)),
							clusterV4Prefix:     types.NewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							aggregateV6Prefix120: types.NewPathForPrefix(netip.MustParsePrefix(aggregateV6Prefix120)),
							clusterV6Prefix:      types.NewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRPMultiPaths,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRPMultiPaths,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 24),
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							clusterIPSvcAdvertWithSelectorAndPrefixLen(redSvcSelector, 120),
							clusterIPSvcAdvertWithSelector(redSvcSelector),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

			var (
				testBGPInstance = instance.NewFakeBGPInstance()
				ceeBGPInstance  = &EnterpriseBGPInstance{
					Name:   testBGPInstance.Name,
					Router: testBGPInstance.Router,
				}
				mockPeerConfigStore = store.NewMockBGPCPResourceStore[*v1.IsovalentBGPPeerConfig]()
				mockAdvertStore     = store.NewMockBGPCPResourceStore[*v1.IsovalentBGPAdvertisement]()
				svcDiffstore        = store.NewFakeDiffStore[*slim_corev1.Service]()
				epDiffStore         = store.NewFakeDiffStore[*k8s.Endpoints]()
			)

			ceeParams := ServiceReconcilerIn{
				In:         cell.In{},
				Lifecycle:  &cell.DefaultLifecycle{},
				Cfg:        defaultConfig,
				BGPConfig:  config.Config{Enabled: true, StatusReportEnabled: false},
				Logger:     logger,
				Upgrader:   newUpgraderMock(testBGPInstanceConfig),
				NSProvider: newMockNodeStatusProvider(),
				PeerAdvert: &IsovalentAdvertisement{
					logger:      logger,
					peerConfigs: mockPeerConfigStore,
					adverts:     mockAdvertStore,
				},
				SvcDiffStore: svcDiffstore,
				EPDiffStore:  epDiffStore,
				Signaler:     signaler.NewBGPCPSignaler(),
			}

			ceeReconciler := NewServiceReconciler(ceeParams).Reconciler.(*ServiceReconciler)

			ceeReconciler.Init(testBGPInstance)
			defer ceeReconciler.Cleanup(testBGPInstance)

			for _, peerConfig := range tt.peerConfigs {
				mockPeerConfigStore.Upsert(peerConfig)
			}

			for _, svc := range tt.services {
				svcDiffstore.Upsert(svc)
			}

			for _, ep := range tt.endpoints {
				epDiffStore.Upsert(ep)
			}

			for _, advert := range tt.advertisements {
				mockAdvertStore.Upsert(advert)
			}

			// reconcile twice to validate idempotency
			for i := 0; i < 2; i++ {
				err := ceeReconciler.Reconcile(context.Background(), reconcilerv2.ReconcileParams{
					BGPInstance: testBGPInstance,
					CiliumNode: &v2.CiliumNode{
						ObjectMeta: metav1.ObjectMeta{
							Name: "node1",
						},
					},
				})
				req.NoError(err)
			}

			// validate new metadata
			serviceMetadataEqual(req, tt.expectedMetadata, ceeReconciler.getMetadata(ceeBGPInstance))

			// validate that advertised paths match expected metadata
			advertisedPrefixesMatch(req, testBGPInstance, tt.expectedMetadata.ServicePaths)
		})
	}
}

// Test_ServiceAndAdvertisementModifications is a step test, in which each step modifies the advertisement or service parameters.
func Test_ServiceAndAdvertisementModifications(t *testing.T) {
	steps := []struct {
		name             string
		upsertAdverts    []*v1.IsovalentBGPAdvertisement
		upsertServices   []*slim_corev1.Service
		upsertEPs        []*k8s.Endpoints
		deleteEPs        []*k8s.Endpoints
		expectedMetadata ServiceReconcilerMetadata
	}{
		{
			name:           "Initial setup - Service (nil) with advertisement( empty )",
			upsertAdverts:  nil,
			upsertServices: nil,
			upsertEPs:      nil,
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconcilerv2.ResourceAFPathsMap{},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: nil,
						{Afi: "ipv6", Safi: "unicast"}: nil,
					},
				},
			},
		},
		{
			name: "Add service (Cluster, External) with advertisement(Cluster) - matching labels",
			upsertAdverts: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(v1.BGPAdvertisement{
					AdvertisementType: v1.BGPServiceAdvert,
					Service: &v1.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{v2.BGPClusterIPAddr},
					},
					Selector: redSvcSelector,
					Attributes: &v2.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard:  []v2.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
						},
					},
				}),
				redV6SvcAdvertWithAdvertisements(v1.BGPAdvertisement{
					AdvertisementType: v1.BGPServiceAdvert,
					Service: &v1.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{v2.BGPClusterIPAddr},
					},
					Selector: redSvcSelector,
					Attributes: &v2.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard:  []v2.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
						},
					},
				}),
			},
			upsertServices: []*slim_corev1.Service{redExternalAndClusterSvc},
			expectedMetadata: ServiceReconcilerMetadata{
				// Only cluster IPs are advertised
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRP,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPClusterIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPClusterIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Update advertisement(Cluster, External) - matching labels",
			upsertAdverts: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(v1.BGPAdvertisement{
					AdvertisementType: v1.BGPServiceAdvert,
					Service: &v1.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{
							v2.BGPClusterIPAddr,
							v2.BGPExternalIPAddr,
						},
					},
					Selector: redSvcSelector,
					Attributes: &v2.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard:  []v2.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
						},
					},
				}),
				redV6SvcAdvertWithAdvertisements(v1.BGPAdvertisement{
					AdvertisementType: v1.BGPServiceAdvert,
					Service: &v1.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{
							v2.BGPClusterIPAddr,
							v2.BGPExternalIPAddr,
						},
					},
					Selector: redSvcSelector,
					Attributes: &v2.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard:  []v2.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
						},
					},
				}),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				// Both cluster and external IPs are advertised
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4Prefix:  types.NewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
							externalV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix:  types.NewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
							externalV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRP,
						redPeer65001v4ExtRPName:     redPeer65001v4ExtRP,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRP,
						redPeer65001v6ExtRPName:     redPeer65001v6ExtRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Update service (Cluster, External) traffic policy local",
			upsertServices: []*slim_corev1.Service{
				svcWithITP(
					svcWithETP(redExternalAndClusterSvc, slim_corev1.ServiceExternalTrafficPolicyLocal),
					slim_corev1.ServiceInternalTrafficPolicyLocal),
			},
			expectedMetadata: ServiceReconcilerMetadata{
				// Both cluster and external IPs are withdrawn, since traffic policy is local and there are no endpoints.
				ServicePaths:         reconcilerv2.ResourceAFPathsMap{},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "Update local endpoints (Cluster, External)",
			upsertEPs: []*k8s.Endpoints{eps1Mixed},
			expectedMetadata: ServiceReconcilerMetadata{
				// Both cluster and external IPs are advertised since there is local endpoint.
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							clusterV4Prefix:  types.NewPathForPrefix(netip.MustParsePrefix(clusterV4Prefix)),
							externalV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							clusterV6Prefix:  types.NewPathForPrefix(netip.MustParsePrefix(clusterV6Prefix)),
							externalV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(externalV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4ClusterRPName: redPeer65001v4ClusterRP,
						redPeer65001v4ExtRPName:     redPeer65001v4ExtRP,
						redPeer65001v6ClusterRPName: redPeer65001v6ClusterRP,
						redPeer65001v6ExtRPName:     redPeer65001v6ExtRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "Delete local endpoints (Cluster, External)",
			deleteEPs: []*k8s.Endpoints{eps1Mixed},
			expectedMetadata: ServiceReconcilerMetadata{
				// Both cluster and external IPs are withdrawn since local endpoints were deleted.
				ServicePaths:         reconcilerv2.ResourceAFPathsMap{},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{
										v2.BGPClusterIPAddr,
										v2.BGPExternalIPAddr,
									},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	req := require.New(t)
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	var (
		testBGPInstance = instance.NewFakeBGPInstance()
		ceeBGPInstance  = &EnterpriseBGPInstance{
			Name:   testBGPInstance.Name,
			Router: testBGPInstance.Router,
		}
		mockPeerConfigStore = store.NewMockBGPCPResourceStore[*v1.IsovalentBGPPeerConfig]()
		mockAdvertStore     = store.NewMockBGPCPResourceStore[*v1.IsovalentBGPAdvertisement]()
		svcDiffstore        = store.NewFakeDiffStore[*slim_corev1.Service]()
		epDiffStore         = store.NewFakeDiffStore[*k8s.Endpoints]()
	)

	ceeParams := ServiceReconcilerIn{
		In:         cell.In{},
		Lifecycle:  &cell.DefaultLifecycle{},
		Cfg:        defaultConfig,
		BGPConfig:  config.Config{Enabled: true, StatusReportEnabled: false},
		Logger:     logger,
		Upgrader:   newUpgraderMock(testBGPInstanceConfig),
		NSProvider: newMockNodeStatusProvider(),
		PeerAdvert: &IsovalentAdvertisement{
			logger:      logger,
			peerConfigs: mockPeerConfigStore,
			adverts:     mockAdvertStore,
		},
		SvcDiffStore: svcDiffstore,
		EPDiffStore:  epDiffStore,
		Signaler:     signaler.NewBGPCPSignaler(),
	}

	ceeReconciler := NewServiceReconciler(ceeParams).Reconciler.(*ServiceReconciler)

	// set peer advert state
	mockPeerConfigStore.Upsert(redPeerConfig)

	ceeReconciler.Init(testBGPInstance)
	defer ceeReconciler.Cleanup(testBGPInstance)

	for _, tt := range steps {
		t.Logf("Running step - %s", tt.name)
		for _, advert := range tt.upsertAdverts {
			mockAdvertStore.Upsert(advert)
		}

		for _, svc := range tt.upsertServices {
			svcDiffstore.Upsert(svc)
		}

		for _, ep := range tt.upsertEPs {
			epDiffStore.Upsert(ep)
		}

		for _, ep := range tt.deleteEPs {
			epDiffStore.Delete(ep)
		}

		err := ceeReconciler.Reconcile(context.Background(), reconcilerv2.ReconcileParams{
			BGPInstance: testBGPInstance,
			CiliumNode: &v2.CiliumNode{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node1",
				},
			},
		})
		req.NoError(err)

		// validate new metadata
		serviceMetadataEqual(req, tt.expectedMetadata, ceeReconciler.getMetadata(ceeBGPInstance))

		// validate that advertised paths match expected metadata
		advertisedPrefixesMatch(req, testBGPInstance, tt.expectedMetadata.ServicePaths)
	}
}

func Test_ServiceVIPSharing(t *testing.T) {
	steps := []struct {
		name             string
		upsertAdverts    []*v1.IsovalentBGPAdvertisement
		upsertServices   []*slim_corev1.Service
		deletetServices  []*slim_corev1.Service
		upsertEPs        []*k8s.Endpoints
		expectedMetadata ServiceReconcilerMetadata
	}{
		{
			name: "Add service 1 (LoadBalancer) with advertisement",
			upsertAdverts: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(v1.BGPAdvertisement{
					AdvertisementType: v1.BGPServiceAdvert,
					Service: &v1.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
					},
					Selector: redSvcSelector,
					Attributes: &v2.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard:  []v2.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
						},
					},
				}),
				redV6SvcAdvertWithAdvertisements(v1.BGPAdvertisement{
					AdvertisementType: v1.BGPServiceAdvert,
					Service: &v1.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
					},
					Selector: redSvcSelector,
					Attributes: &v2.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard:  []v2.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
						},
					},
				}),
			},
			upsertServices: []*slim_corev1.Service{redLBSvc},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:           "Add service 2 (LoadBalancer) with the same VIP",
			upsertServices: []*slim_corev1.Service{redLBSvc2()},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
					redSvc2Key: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4LBRPName: redPeer65001v4LBRP,
						redPeer65001v6LBRPName: redPeer65001v6LBRP,
					},
					redSvc2Key: reconcilerv2.RoutePolicyMap{
						redPeer65001Svc2v4LBRPName: redPeer65001Svc2v4LBRP(),
						redPeer65001Svc2v6LBRPName: redPeer65001Svc2v6LBRP(),
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:            "Delete service 1",
			deletetServices: []*slim_corev1.Service{redLBSvc},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvc2Key: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvc2Key: reconcilerv2.RoutePolicyMap{
						redPeer65001Svc2v4LBRPName: redPeer65001Svc2v4LBRP(),
						redPeer65001Svc2v6LBRPName: redPeer65001Svc2v6LBRP(),
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:            "Delete service 2",
			deletetServices: []*slim_corev1.Service{redLBSvc2()},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths:         reconcilerv2.ResourceAFPathsMap{},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	req := require.New(t)
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	var (
		testBGPInstance = instance.NewFakeBGPInstance()
		ceeBGPInstance  = &EnterpriseBGPInstance{
			Name:   testBGPInstance.Name,
			Router: testBGPInstance.Router,
		}
		mockPeerConfigStore = store.NewMockBGPCPResourceStore[*v1.IsovalentBGPPeerConfig]()
		mockAdvertStore     = store.NewMockBGPCPResourceStore[*v1.IsovalentBGPAdvertisement]()
		svcDiffstore        = store.NewFakeDiffStore[*slim_corev1.Service]()
		epDiffStore         = store.NewFakeDiffStore[*k8s.Endpoints]()
	)

	ceeParams := ServiceReconcilerIn{
		In:         cell.In{},
		Lifecycle:  &cell.DefaultLifecycle{},
		Cfg:        defaultConfig,
		BGPConfig:  config.Config{Enabled: true, StatusReportEnabled: false},
		Logger:     logger,
		Upgrader:   newUpgraderMock(testBGPInstanceConfig),
		NSProvider: newMockNodeStatusProvider(),
		PeerAdvert: &IsovalentAdvertisement{
			logger:      logger,
			peerConfigs: mockPeerConfigStore,
			adverts:     mockAdvertStore,
		},
		SvcDiffStore: svcDiffstore,
		EPDiffStore:  epDiffStore,
		Signaler:     signaler.NewBGPCPSignaler(),
	}

	ceeReconciler := NewServiceReconciler(ceeParams).Reconciler.(*ServiceReconciler)

	// set peer advert state
	mockPeerConfigStore.Upsert(redPeerConfig)

	ceeReconciler.Init(testBGPInstance)
	defer ceeReconciler.Cleanup(testBGPInstance)

	for _, tt := range steps {
		t.Logf("Running step - %s", tt.name)
		for _, advert := range tt.upsertAdverts {
			mockAdvertStore.Upsert(advert)
		}

		for _, svc := range tt.upsertServices {
			svcDiffstore.Upsert(svc)
		}

		for _, svc := range tt.deletetServices {
			svcDiffstore.Delete(svc)
		}

		for _, ep := range tt.upsertEPs {
			epDiffStore.Upsert(ep)
		}

		err := ceeReconciler.Reconcile(context.Background(), reconcilerv2.ReconcileParams{
			BGPInstance: testBGPInstance,
			CiliumNode:  testCiliumNodeConfig,
		})
		req.NoError(err)

		// validate new metadata
		serviceMetadataEqual(req, tt.expectedMetadata, ceeReconciler.getMetadata(ceeBGPInstance))

		// validate that advertised paths match expected metadata
		advertisedPrefixesMatch(req, testBGPInstance, tt.expectedMetadata.ServicePaths)
	}
}

func Test_ServiceAdvertisementWithPeerIPChange(t *testing.T) {
	steps := []struct {
		name             string
		peers            []v1.IsovalentBGPNodePeer
		upsertAdverts    []*v1.IsovalentBGPAdvertisement
		upsertServices   []*slim_corev1.Service
		deletetServices  []*slim_corev1.Service
		upsertEPs        []*k8s.Endpoints
		expectedMetadata ServiceReconcilerMetadata
	}{
		{
			name: "Add service and advertisement",
			peers: []v1.IsovalentBGPNodePeer{
				{
					Name:        "red-peer-65001",
					PeerAddress: ptr.To[string]("10.10.10.1"),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "peer-config-red",
					},
				},
			},
			upsertAdverts: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(v1.BGPAdvertisement{
					AdvertisementType: v1.BGPServiceAdvert,
					Service: &v1.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
					},
					Selector: redSvcSelector,
					Attributes: &v2.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard:  []v2.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
						},
					},
				}),
				redV6SvcAdvertWithAdvertisements(v1.BGPAdvertisement{
					AdvertisementType: v1.BGPServiceAdvert,
					Service: &v1.BGPServiceOptions{
						Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
					},
					Selector: redSvcSelector,
					Attributes: &v2.BGPAttributes{
						Communities: &v2.BGPCommunities{
							Standard:  []v2.BGPStandardCommunity{"65535:65281"},
							WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
						},
					},
				}),
			},
			upsertServices: []*slim_corev1.Service{redLBSvc},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4LBRPName: &types.RoutePolicy{
							Name: redPeer65001v4LBRPName,
							Type: types.RoutePolicyTypeExport,
							Statements: []*types.RoutePolicyStatement{
								{
									Conditions: types.RoutePolicyConditions{
										MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
										MatchPrefixes: []*types.RoutePolicyPrefixMatch{
											{
												CIDR:         netip.MustParsePrefix(ingressV4Prefix),
												PrefixLenMin: 32,
												PrefixLenMax: 32,
											},
										},
									},
									Actions: types.RoutePolicyActions{
										RouteAction:    types.RoutePolicyActionAccept,
										AddCommunities: []string{"65535:65281"},
									},
								},
							},
						},
						redPeer65001v6LBRPName: &types.RoutePolicy{
							Name: redPeer65001v6LBRPName,
							Type: types.RoutePolicyTypeExport,
							Statements: []*types.RoutePolicyStatement{
								{
									Conditions: types.RoutePolicyConditions{
										MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
										MatchPrefixes: []*types.RoutePolicyPrefixMatch{
											{
												CIDR:         netip.MustParsePrefix(ingressV6Prefix),
												PrefixLenMin: 128,
												PrefixLenMax: 128,
											},
										},
									},
									Actions: types.RoutePolicyActions{
										RouteAction:    types.RoutePolicyActionAccept,
										AddCommunities: []string{"65535:65281"},
									},
								},
							},
						},
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					PeerID{Name: "red-peer-65001", Address: "10.10.10.1"}: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Change peer IP address",
			peers: []v1.IsovalentBGPNodePeer{
				{
					Name:        "red-peer-65001",
					PeerAddress: ptr.To[string]("10.10.10.99"),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "peer-config-red",
					},
				},
			},
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4LBRPName: &types.RoutePolicy{
							Name: redPeer65001v4LBRPName,
							Type: types.RoutePolicyTypeExport,
							Statements: []*types.RoutePolicyStatement{
								{
									Conditions: types.RoutePolicyConditions{
										MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.99")},
										MatchPrefixes: []*types.RoutePolicyPrefixMatch{
											{
												CIDR:         netip.MustParsePrefix(ingressV4Prefix),
												PrefixLenMin: 32,
												PrefixLenMax: 32,
											},
										},
									},
									Actions: types.RoutePolicyActions{
										RouteAction:    types.RoutePolicyActionAccept,
										AddCommunities: []string{"65535:65281"},
									},
								},
							},
						},
						redPeer65001v6LBRPName: &types.RoutePolicy{
							Name: redPeer65001v6LBRPName,
							Type: types.RoutePolicyTypeExport,
							Statements: []*types.RoutePolicyStatement{
								{
									Conditions: types.RoutePolicyConditions{
										MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.99")},
										MatchPrefixes: []*types.RoutePolicyPrefixMatch{
											{
												CIDR:         netip.MustParsePrefix(ingressV6Prefix),
												PrefixLenMin: 128,
												PrefixLenMax: 128,
											},
										},
									},
									Actions: types.RoutePolicyActions{
										RouteAction:    types.RoutePolicyActionAccept,
										AddCommunities: []string{"65535:65281"},
									},
								},
							},
						},
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					PeerID{Name: "red-peer-65001", Address: "10.10.10.99"}: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{
							{
								AdvertisementType: v1.BGPServiceAdvert,
								Service: &v1.BGPServiceOptions{
									Addresses: []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr},
								},
								Selector: redSvcSelector,
								Attributes: &v2.BGPAttributes{
									Communities: &v2.BGPCommunities{
										Standard:  []v2.BGPStandardCommunity{"65535:65281"},
										WellKnown: []v2.BGPWellKnownCommunity{"no-export"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	req := require.New(t)
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	var (
		testBGPInstance = instance.NewFakeBGPInstance()
		ceeBGPInstance  = &EnterpriseBGPInstance{
			Name:   testBGPInstance.Name,
			Router: testBGPInstance.Router,
		}
		mockPeerConfigStore = store.NewMockBGPCPResourceStore[*v1.IsovalentBGPPeerConfig]()
		mockAdvertStore     = store.NewMockBGPCPResourceStore[*v1.IsovalentBGPAdvertisement]()
		svcDiffstore        = store.NewFakeDiffStore[*slim_corev1.Service]()
		epDiffStore         = store.NewFakeDiffStore[*k8s.Endpoints]()
	)

	ceeParams := ServiceReconcilerIn{
		In:         cell.In{},
		Lifecycle:  &cell.DefaultLifecycle{},
		Cfg:        defaultConfig,
		BGPConfig:  config.Config{Enabled: true, StatusReportEnabled: false},
		Logger:     logger,
		Upgrader:   newUpgraderMock(testBGPInstanceConfig),
		NSProvider: newMockNodeStatusProvider(),
		PeerAdvert: &IsovalentAdvertisement{
			logger:      logger,
			peerConfigs: mockPeerConfigStore,
			adverts:     mockAdvertStore,
		},
		SvcDiffStore: svcDiffstore,
		EPDiffStore:  epDiffStore,
		Signaler:     signaler.NewBGPCPSignaler(),
	}

	ceeReconciler := NewServiceReconciler(ceeParams).Reconciler.(*ServiceReconciler)

	mockPeerConfigStore.Upsert(redPeerConfig)

	ceeReconciler.Init(testBGPInstance)
	defer ceeReconciler.Cleanup(testBGPInstance)

	for _, tt := range steps {
		t.Logf("Running step - %s", tt.name)

		// set peers in the node instance
		nodeInstanceCopy := testBGPInstanceConfig.DeepCopy()
		nodeInstanceCopy.Peers = tt.peers
		ceeReconciler.upgrader = newUpgraderMock(nodeInstanceCopy)

		for _, advert := range tt.upsertAdverts {
			mockAdvertStore.Upsert(advert)
		}

		for _, svc := range tt.upsertServices {
			svcDiffstore.Upsert(svc)
		}

		for _, svc := range tt.deletetServices {
			svcDiffstore.Delete(svc)
		}

		for _, ep := range tt.upsertEPs {
			epDiffStore.Upsert(ep)
		}

		err := ceeReconciler.Reconcile(context.Background(), reconcilerv2.ReconcileParams{
			BGPInstance: testBGPInstance,
			CiliumNode:  testCiliumNodeConfig,
		})
		req.NoError(err)

		// validate new metadata
		serviceMetadataEqual(req, tt.expectedMetadata, ceeReconciler.getMetadata(ceeBGPInstance))

		// validate that advertised paths match expected metadata
		advertisedPrefixesMatch(req, testBGPInstance, tt.expectedMetadata.ServicePaths)
	}
}

func Test_ServiceNodeMaintenance(t *testing.T) {
	steps := []struct {
		name             string
		peers            []v1.IsovalentBGPNodePeer
		upsertAdverts    []*v1.IsovalentBGPAdvertisement
		upsertServices   []*slim_corev1.Service
		nodeStatus       NodeStatus
		expectedMetadata ServiceReconcilerMetadata
	}{
		{
			name: "Add service and advertisement - advertise normally",
			peers: []v1.IsovalentBGPNodePeer{
				{
					Name:        "red-peer-65001",
					PeerAddress: ptr.To[string]("10.10.10.1"),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "peer-config-red",
					},
				},
			},
			upsertAdverts: []*v1.IsovalentBGPAdvertisement{
				redSvcAdvertWithAdvertisements(lbSvcAdvertWithSelector(redSvcSelector)),
			},
			upsertServices: []*slim_corev1.Service{redLBSvc},
			nodeStatus:     NodeReady,
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4LBRPName: &types.RoutePolicy{
							Name: redPeer65001v4LBRPName,
							Type: types.RoutePolicyTypeExport,
							Statements: []*types.RoutePolicyStatement{
								{
									Conditions: types.RoutePolicyConditions{
										MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
										MatchPrefixes: []*types.RoutePolicyPrefixMatch{
											{
												CIDR:         netip.MustParsePrefix(ingressV4Prefix),
												PrefixLenMin: 32,
												PrefixLenMax: 32,
											},
										},
									},
									Actions: types.RoutePolicyActions{
										RouteAction:    types.RoutePolicyActionAccept,
										AddCommunities: []string{"65535:65281"},
									},
								},
							},
						},
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{},
					},
				},
			},
		},
		{
			name: "Update node status - node maintenance, advertise GS community",
			peers: []v1.IsovalentBGPNodePeer{
				{
					Name:        "red-peer-65001",
					PeerAddress: ptr.To[string]("10.10.10.1"),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "peer-config-red",
					},
				},
			},
			upsertAdverts:  nil,
			upsertServices: nil,
			nodeStatus:     NodeMaintenance,
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4LBRPName: &types.RoutePolicy{
							Name: redPeer65001v4LBRPName,
							Type: types.RoutePolicyTypeExport,
							Statements: []*types.RoutePolicyStatement{
								{
									Conditions: types.RoutePolicyConditions{
										MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
										MatchPrefixes: []*types.RoutePolicyPrefixMatch{
											{
												CIDR:         netip.MustParsePrefix(ingressV4Prefix),
												PrefixLenMin: 32,
												PrefixLenMax: 32,
											},
										},
									},
									Actions: types.RoutePolicyActions{
										RouteAction:    types.RoutePolicyActionAccept,
										AddCommunities: []string{"65535:65281", gracefulShutdownCommunityValue},
									},
								},
							},
						},
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{},
					},
				},
			},
		},
		{
			name: "Update node status - node maintenance timeout expired, withdraw",
			peers: []v1.IsovalentBGPNodePeer{
				{
					Name:        "red-peer-65001",
					PeerAddress: ptr.To[string]("10.10.10.1"),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "peer-config-red",
					},
				},
			},
			upsertAdverts:  nil,
			upsertServices: nil,
			nodeStatus:     NodeMaintenanceTimeExpired,
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4LBRPName: &types.RoutePolicy{
							Name: redPeer65001v4LBRPName,
							Type: types.RoutePolicyTypeExport,
							Statements: []*types.RoutePolicyStatement{
								{
									Conditions: types.RoutePolicyConditions{
										MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
										MatchPrefixes: []*types.RoutePolicyPrefixMatch{
											{
												CIDR:         netip.MustParsePrefix(ingressV4Prefix),
												PrefixLenMin: 32,
												PrefixLenMax: 32,
											},
										},
									},
									Actions: types.RoutePolicyActions{
										RouteAction:    types.RoutePolicyActionAccept,
										AddCommunities: []string{"65535:65281", gracefulShutdownCommunityValue},
									},
								},
							},
						},
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{},
					},
				},
			},
		},
		{
			name: "Update node status - node ready, advertise again",
			peers: []v1.IsovalentBGPNodePeer{
				{
					Name:        "red-peer-65001",
					PeerAddress: ptr.To[string]("10.10.10.1"),
					PeerConfigRef: &v1.PeerConfigReference{
						Name: "peer-config-red",
					},
				},
			},
			upsertAdverts:  nil,
			upsertServices: nil,
			nodeStatus:     NodeReady,
			expectedMetadata: ServiceReconcilerMetadata{
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					redSvcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix)),
						},
					},
				},
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					redSvcKey: reconcilerv2.RoutePolicyMap{
						redPeer65001v4LBRPName: &types.RoutePolicy{
							Name: redPeer65001v4LBRPName,
							Type: types.RoutePolicyTypeExport,
							Statements: []*types.RoutePolicyStatement{
								{
									Conditions: types.RoutePolicyConditions{
										MatchNeighbors: []netip.Addr{netip.MustParseAddr("10.10.10.1")},
										MatchPrefixes: []*types.RoutePolicyPrefixMatch{
											{
												CIDR:         netip.MustParsePrefix(ingressV4Prefix),
												PrefixLenMin: 32,
												PrefixLenMax: 32,
											},
										},
									},
									Actions: types.RoutePolicyActions{
										RouteAction:    types.RoutePolicyActionAccept,
										AddCommunities: []string{"65535:65281"},
									},
								},
							},
						},
					},
				},
				ServiceAdvertisements: PeerAdvertisements{
					testPeerID: FamilyAdvertisements{
						{Afi: "ipv4", Safi: "unicast"}: []v1.BGPAdvertisement{
							lbSvcAdvertWithSelector(redSvcSelector),
						},
						{Afi: "ipv6", Safi: "unicast"}: []v1.BGPAdvertisement{},
					},
				},
			},
		},
	}

	req := require.New(t)
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	var (
		testBGPInstance = instance.NewFakeBGPInstance()
		ceeBGPInstance  = &EnterpriseBGPInstance{
			Name:   testBGPInstance.Name,
			Router: testBGPInstance.Router,
		}
		mockPeerConfigStore = store.NewMockBGPCPResourceStore[*v1.IsovalentBGPPeerConfig]()
		mockAdvertStore     = store.NewMockBGPCPResourceStore[*v1.IsovalentBGPAdvertisement]()
		svcDiffstore        = store.NewFakeDiffStore[*slim_corev1.Service]()
		epDiffStore         = store.NewFakeDiffStore[*k8s.Endpoints]()
	)

	nodeStatus := newMockNodeStatusProvider()

	ceeParams := ServiceReconcilerIn{
		In:        cell.In{},
		Lifecycle: &cell.DefaultLifecycle{},
		Cfg: Config{
			MaintenanceGracefulShutdownEnabled: true,
			MaintenanceWithdrawTime:            10 * time.Second,
		},
		BGPConfig:  config.Config{Enabled: true, StatusReportEnabled: false},
		Logger:     logger,
		Upgrader:   newUpgraderMock(testBGPInstanceConfig),
		NSProvider: nodeStatus,
		PeerAdvert: &IsovalentAdvertisement{
			logger:      logger,
			peerConfigs: mockPeerConfigStore,
			adverts:     mockAdvertStore,
		},
		SvcDiffStore: svcDiffstore,
		EPDiffStore:  epDiffStore,
		Signaler:     signaler.NewBGPCPSignaler(),
	}

	ceeReconciler := NewServiceReconciler(ceeParams).Reconciler.(*ServiceReconciler)

	mockPeerConfigStore.Upsert(redPeerConfig)

	ceeReconciler.Init(testBGPInstance)
	defer ceeReconciler.Cleanup(testBGPInstance)

	for _, tt := range steps {
		t.Logf("Running step - %s", tt.name)

		// set peers in the node instance
		nodeInstanceCopy := testBGPInstanceConfig.DeepCopy()
		nodeInstanceCopy.Peers = tt.peers
		ceeReconciler.upgrader = newUpgraderMock(nodeInstanceCopy)

		for _, advert := range tt.upsertAdverts {
			mockAdvertStore.Upsert(advert)
		}

		for _, svc := range tt.upsertServices {
			svcDiffstore.Upsert(svc)
		}

		// set node status
		nodeStatus.SetNodeStatus(tt.nodeStatus)

		err := ceeReconciler.Reconcile(context.Background(), reconcilerv2.ReconcileParams{
			BGPInstance: testBGPInstance,
			CiliumNode:  testCiliumNodeConfig,
		})
		req.NoError(err)

		// validate new metadata
		serviceMetadataEqual(req, tt.expectedMetadata, ceeReconciler.getMetadata(ceeBGPInstance))

		// validate that advertised paths match expected metadata
		advertisedPrefixesMatch(req, testBGPInstance, tt.expectedMetadata.ServicePaths)
	}
}

func serviceMetadataEqual(req *require.Assertions, expectedMetadata, runningMetadata ServiceReconcilerMetadata) {
	req.Truef(PeerAdvertisementsEqual(expectedMetadata.ServiceAdvertisements, runningMetadata.ServiceAdvertisements),
		"ServiceAdvertisements mismatch, expected: %v, got: %v", expectedMetadata.ServiceAdvertisements, runningMetadata.ServiceAdvertisements)

	req.Lenf(runningMetadata.ServicePaths, len(expectedMetadata.ServicePaths),
		"ServicePaths length mismatch, expected: %v, got: %v", expectedMetadata.ServicePaths, runningMetadata.ServicePaths)

	for svc, expectedSvcPaths := range expectedMetadata.ServicePaths {
		runningSvcPaths, exists := runningMetadata.ServicePaths[svc]
		req.Truef(exists, "Service not found in running: %v", svc)

		runningFamilyPaths := make(map[types.Family]map[string]struct{})
		for family, paths := range runningSvcPaths {
			pathSet := make(map[string]struct{})

			for pathKey := range paths {
				pathSet[pathKey] = struct{}{}
			}
			runningFamilyPaths[family] = pathSet
		}

		expectedFamilyPaths := make(map[types.Family]map[string]struct{})
		for family, paths := range expectedSvcPaths {
			pathSet := make(map[string]struct{})

			for pathKey := range paths {
				pathSet[pathKey] = struct{}{}
			}
			expectedFamilyPaths[family] = pathSet
		}

		req.Equal(expectedFamilyPaths, runningFamilyPaths)
	}

	req.Equalf(expectedMetadata.ServiceRoutePolicies, runningMetadata.ServiceRoutePolicies,
		"ServiceRoutePolicies mismatch, expected: %v, got: %v", expectedMetadata.ServiceRoutePolicies, runningMetadata.ServiceRoutePolicies)
}

func advertisedPrefixesMatch(req *require.Assertions, bgpInstance *instance.BGPInstance, expectedPaths reconcilerv2.ResourceAFPathsMap) {
	expected := make(map[string]*types.Path)
	for _, svcPaths := range expectedPaths {
		for _, afPaths := range svcPaths {
			for _, path := range afPaths {
				expected[path.NLRI.String()] = path
			}
		}
	}

	advertised := make(map[string]*types.Path)
	routes, err := bgpInstance.Router.GetRoutes(context.Background(), &types.GetRoutesRequest{TableType: types.TableTypeLocRIB})
	req.NoError(err)
	for _, route := range routes.Routes {
		for _, path := range route.Paths {
			advertised[path.NLRI.String()] = path
		}
	}

	expPrefixes := slices.Collect(maps.Keys(expected))
	advPrefixes := slices.Collect(maps.Keys(advertised))
	req.ElementsMatchf(expPrefixes, advPrefixes, "advertised prefixes do not match expected metadata, expected: %v, got: %v", expPrefixes, advPrefixes)
}
