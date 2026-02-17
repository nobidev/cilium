// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package addressing

import (
	"cmp"
	"fmt"
	"net/netip"
	"testing"
	"testing/synctest"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/go-openapi/strfmt"
	"github.com/stretchr/testify/assert"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/api/v1/models"
	"github.com/cilium/cilium/enterprise/api/v1/server/restapi/network"
	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/time"
)

func TestPrivNetAPI_GetPrivateNetworkAddressing(t *testing.T) {
	initPrivNetAPI := func(t *testing.T, cfg cfg, pod k8s.LocalPod) *PrivNetAPI {
		t.Helper()

		db := statedb.New()
		pods, err := k8s.NewPodTable(db)
		if err != nil {
			t.Fatalf("NewPodTable: %s", err)
		}

		wtxn := db.WriteTxn(pods)
		pods.Insert(wtxn, pod)
		wtxn.Commit()

		privNets, err := tables.NewPrivateNetworksTable(db)
		if err != nil {
			t.Fatalf("NewPrivateNetworksTable: %s", err)
		}
		subnets, err := tables.NewSubnetTable(db)
		if err != nil {
			t.Fatalf("NewPrivateNetworksTable: %s", err)
		}
		wtxn = db.WriteTxn(privNets, subnets)
		privNets.Insert(wtxn,
			tables.PrivateNetwork{
				Name: "green-network",
				ID:   1,
			})
		subnets.Insert(wtxn,
			tables.Subnet{
				SubnetSpec: tables.SubnetSpec{
					Network:   "green-network",
					NetworkID: 1,
					Name:      "subnet1",
					CIDRv4:    netip.MustParsePrefix("192.168.11.0/24"),
					CIDRv6:    netip.MustParsePrefix("fd10:0:150::/64"),
				},
			})
		subnets.Insert(wtxn,
			tables.Subnet{
				SubnetSpec: tables.SubnetSpec{
					Network:   "green-network",
					NetworkID: 1,
					Name:      "subnet2",
					CIDRv4:    netip.MustParsePrefix("192.168.52.0/24"),
					CIDRv6:    netip.MustParsePrefix("fd10:0:152::/64"),
				},
			},
		)
		subnets.Insert(wtxn,
			tables.Subnet{
				SubnetSpec: tables.SubnetSpec{
					Network:   "green-network",
					NetworkID: 1,
					Name:      "subnet3",
					CIDRv4:    netip.MustParsePrefix("192.168.10.0/24"),
					CIDRv6:    netip.MustParsePrefix("fd10:0:140::/64"),
				},
			},
		)
		privNets.Insert(wtxn,
			tables.PrivateNetwork{
				Name: "blue-network",
				ID:   2,
			})
		subnets.Insert(wtxn,
			tables.Subnet{
				SubnetSpec: tables.SubnetSpec{
					Network:   "blue-network",
					NetworkID: 2,
					Name:      "subnet1",
					CIDRv4:    netip.MustParsePrefix("192.168.22.0/24"),
				},
			})

		wtxn.Commit()

		return &PrivNetAPI{
			db:              db,
			cfg:             cfg,
			log:             hivetest.Logger(t),
			pods:            pods,
			privateNetworks: privNets,
			subnets:         subnets,
		}
	}

	newPod := func(namespace, name, uid string, annotations map[string]string) k8s.LocalPod {
		return k8s.LocalPod{Pod: &slim_core_v1.Pod{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Namespace:   namespace,
				Name:        name,
				UID:         k8stypes.UID(uid),
				Annotations: annotations,
			},
		}}
	}

	cfgDefault := cfg{
		privateNetworkConfig: config.Config{
			Common: config.Common{
				Enabled: true,
			},
			Mode: config.ModeDefault,
		},
		enableIPv4: true,
		enableIPv6: true,
	}
	cfgPrivNetDisabled := cfg{
		privateNetworkConfig: config.Config{
			Common: config.Common{
				Enabled: false,
			},
		},
	}
	cfgIPv4Only := cfg{
		privateNetworkConfig: config.Config{
			Common: config.Common{
				Enabled: true,
			},
			Mode: config.ModeDefault,
		},
		enableIPv4: true,
		enableIPv6: false,
	}
	cfgIPv6Only := cfg{
		privateNetworkConfig: config.Config{
			Common: config.Common{
				Enabled: true,
			},
			Mode: config.ModeDefault,
		},
		enableIPv4: false,
		enableIPv6: true,
	}

	activatedAtActive := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	activatedAtInactive := time.Time{}

	type override struct {
		network   *string
		subnet    *string
		namespace string
		name      string
		uid       string
	}
	tests := []struct {
		name           string
		cfg            *cfg
		pod            k8s.LocalPod
		override       override
		wantAddressing *models.PrivateNetworkAddressing
		wantErr        string
	}{
		{
			name: "no network attachment annotation",
			cfg:  &cfgPrivNetDisabled,
			pod:  newPod("default", "client", "uid", nil),
		},
		{
			name: "no network attachment annotation",
			pod:  newPod("default", "client", "uid", nil),
		},
		{
			name: "valid network attachment annotation",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtActive),
				Network:     "green-network",
				Address: &models.AddressPair{
					IPV4: "192.168.11.11",
					IPV6: "fd10:0:150::11",
				},
				Mac: "00:50:56:ad:11:02",
			},
		},
		{
			name: "valid inactive pod",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation:         `{"network": "green-network", "ipv4": "192.168.11.13", "ipv6": "fd10:0:150::13", "mac": "00:69:af:ca:8e:34"}`,
					types.PrivateNetworkInactiveAnnotation: "true",
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtInactive),
				Network:     "green-network",
				Address: &models.AddressPair{
					IPV4: "192.168.11.13",
					IPV6: "fd10:0:150::13",
				},
				Mac: "00:69:af:ca:8e:34",
			},
		},
		{
			name: "pod nonexistent",
			pod:  newPod("default", "client", "uid", nil),
		},
		{
			name: "pod nonexistent in namespace",
			pod:  newPod("default", "client", "uid", nil),
			override: override{
				name: "workload",
			},
			wantErr: "pod default/workload not found",
		},
		{
			name: "pod nonexistent in namespace",
			pod:  newPod("default", "client", "uid", nil),
			override: override{
				namespace: "tenant1",
			},
			wantErr: "pod tenant1/client not found",
		},
		{
			name: "pod UID not matching",
			pod:  newPod("default", "client", "uid", nil),
			override: override{
				uid: "some-other-uid",
			},
			wantErr: "UID does not match pod object in store",
		},
		{
			name: "network nonexistent",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "nonexistent-network", "ipv4": "10.20.0.12", "ipv6": "fd20:0:150::12", "mac": "00:60:8c:b1:91:21"}`,
				},
			),
			wantErr: fmt.Sprintf(`invalid network "nonexistent-network" in %q annotation`, types.PrivateNetworkAnnotation),
		},
		{
			name: "invalid attachment annotation",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network" "ipv4": "192.168.11.11" "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantErr: fmt.Sprintf(`invalid value in %q annotation`, types.PrivateNetworkAnnotation),
		},
		{
			name: "invalid inactive annotation",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation:         `{"network": "blue-network", "ipv4": "10.10.0.14", "ipv6": "fd10:0:150::14", "mac": "00:69:af:ca:8e:34"}`,
					types.PrivateNetworkInactiveAnnotation: "foobar",
				},
			),
			wantErr: fmt.Sprintf(`invalid value in %q annotation`, types.PrivateNetworkInactiveAnnotation),
		},
		{
			name: "invalid IPv4",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "fd10:0:150::15", "ipv6": "fd10:0:150::15", "mac": "00:df:a2:ca:8e:44"}`,
				},
			),
			wantErr: fmt.Sprintf(`invalid IPv4 address "fd10:0:150::15" in %q annotation`, types.PrivateNetworkAnnotation),
		},
		{
			name: "invalid IPv6",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.16", "ipv6": "192.168.11.16", "mac": "00:a3:af:ca:8e:66"}`,
				},
			),
			wantErr: fmt.Sprintf(`invalid IPv6 address "192.168.11.16" in %q annotation`, types.PrivateNetworkAnnotation),
		},
		{
			name: "IPv4 not in prefixes",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "10.10.0.17", "ipv6": "fd10:0:150::17", "mac": "00:69:af:ca:8e:34"}`,
				},
			),
			wantErr: "requested IP 10.10.0.17 not in range of",
		},
		{
			name: "IPv6 not in prefixes",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.18", "ipv6": "face::bead", "mac": "00:a8:c0:01:2d:22"}`,
				},
			),
			wantErr: "requested IP face::bead not in range of",
		},
		{
			name: "requesting IPv6 from IPv4-only network",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "blue-network", "ipv4": "192.168.22.11", "ipv6": "fd10:0:250::11", "mac": "00:a8:c0:01:2d:22"}`,
				},
			),
			wantErr: "requested IP fd10:0:250::11 not in range of",
		},
		{
			name: "requesting IPv4 in IPv6-only configuration",
			cfg:  &cfgIPv6Only,
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantErr: fmt.Sprintf(`invalid IPv6 address "invalid IP" in %q annotation`, types.PrivateNetworkAnnotation),
		},
		{
			name: "requesting IPv6 in IPv4-only configuration",
			cfg:  &cfgIPv4Only,
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv6": "fd10:0:150::11",  "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantErr: fmt.Sprintf(`invalid IPv4 address "invalid IP" in %q annotation`, types.PrivateNetworkAnnotation),
		},
		{
			name: "requesting IPv4 and IPv6 in IPv6-only configuration",
			cfg:  &cfgIPv6Only,
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtActive),
				Network:     "green-network",
				Address: &models.AddressPair{
					IPV6: "fd10:0:150::11",
				},
				Mac: "00:50:56:ad:11:02",
			},
		},
		{
			name: "requesting IPv4 and IPv6 in IPv4-only configuration",
			cfg:  &cfgIPv4Only,
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtActive),
				Network:     "green-network",
				Address: &models.AddressPair{
					IPV4: "192.168.11.11",
				},
				Mac: "00:50:56:ad:11:02",
			},
		},
		{
			name: "IPv4 and IPv6 not in same subnet",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.52.17", "ipv6": "fd10:0:150::17", "mac": "00:69:af:ca:8e:34"}`,
				},
			),
			wantErr: "requested IP fd10:0:150::17 not in range of",
		},
		{
			name: "network attachement in conflicting subnet",
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantErr: "requested IP fd10:0:150::11 not in range of the subnet of the IP 192.168.10.11",
		},
		{
			name:     "CNI configuration specifies network, but subnet is missing",
			override: override{network: ptr.To("green-network")},
			pod:      newPod("default", "client", "uid", nil),
			wantErr:  "both network and subnet must be set in CNI configuration if one is provided",
		},
		{
			name:     "CNI configuration specifies subnet, but network is missing",
			override: override{subnet: ptr.To("subnet1")},
			pod:      newPod("default", "client", "uid", nil),
			wantErr:  "both network and subnet must be set in CNI configuration if one is provided",
		},
		{
			name:     "CNI configuration specifies network, but private networks is disabled",
			cfg:      &cfgPrivNetDisabled,
			override: override{network: ptr.To("green-network"), subnet: ptr.To("subnet1")},
			pod:      newPod("default", "client", "uid", nil),
			wantErr:  "target network set in CNI configuration, but private networks is disabled",
		},
		{
			name:     "CNI configuration specifies network, but attachment is missing",
			override: override{network: ptr.To("green-network"), subnet: ptr.To("subnet1")},
			pod:      newPod("default", "client", "uid", nil),
			wantErr:  fmt.Sprintf(`target network set in CNI configuration, but %q annotation is missing on pod default/client`, types.PrivateNetworkAnnotation),
		},
		{
			name:     "mismatching CNI configuration and attachment network",
			override: override{network: ptr.To("blue-network"), subnet: ptr.To("subnet1")},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.10.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
				}),
			wantErr: fmt.Sprintf(`mismatching target network in CNI configuration ("blue-network") and %q annotation on pod default/client ("green-network")`, types.PrivateNetworkAnnotation),
		},
		{
			name:     "mismatching CNI configuration and target subnet network",
			override: override{network: ptr.To("green-network"), subnet: ptr.To("subnet2")},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
				}),
			wantErr: `requested IPs are not in range of the requested subnet ("subnet2")`,
		},
		{
			name:     "valid network attachment annotation, matching CNI configuration",
			override: override{network: ptr.To("green-network"), subnet: ptr.To("subnet1")},
			pod: newPod("default", "client", "uid",
				map[string]string{
					types.PrivateNetworkAnnotation: `{"network": "green-network", "ipv4": "192.168.11.11", "ipv6": "fd10:0:150::11", "mac": "00:50:56:ad:11:02"}`,
				},
			),
			wantAddressing: &models.PrivateNetworkAddressing{
				ActivatedAt: strfmt.DateTime(activatedAtActive),
				Network:     "green-network",
				Address: &models.AddressPair{
					IPV4: "192.168.11.11",
					IPV6: "fd10:0:150::11",
				},
				Mac: "00:50:56:ad:11:02",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := cmp.Or(tt.cfg, &cfgDefault)
				n := initPrivNetAPI(t, *cfg, tt.pod)

				// override requested pod attributes to test mismatches
				name := cmp.Or(tt.override.name, tt.pod.Name)
				namespace := cmp.Or(tt.override.namespace, tt.pod.Namespace)
				uid := cmp.Or(tt.override.uid, string(tt.pod.UID))
				addressing, err := n.GetPrivateNetworkAddressing(network.GetNetworkPrivateAddressingParams{
					Network:      tt.override.network,
					Subnet:       tt.override.subnet,
					PodName:      name,
					PodNamespace: namespace,
					PodUID:       uid,
					Ifname:       "eth0",
				})
				if tt.wantErr != "" {
					assert.ErrorContains(t, err, tt.wantErr)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tt.wantAddressing, addressing)
				}
			})
		})
	}
}
