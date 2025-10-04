//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package phantom

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/clustermesh/store"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

func TestPhantomServiceConverter(t *testing.T) {
	tests := []struct {
		name     string
		svc      slim_corev1.Service
		expected store.ClusterService
		deleted  bool
	}{
		{
			name: "Phantom service",
			svc: slim_corev1.Service{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:        "foo",
					Namespace:   "bar",
					Annotations: map[string]string{"service.isovalent.com/phantom": "true"},
				},
				Spec: slim_corev1.ServiceSpec{
					ClusterIP: "127.0.0.1",
					Type:      slim_corev1.ServiceTypeLoadBalancer,
					Ports: []slim_corev1.ServicePort{
						{Name: "http", Protocol: slim_corev1.ProtocolTCP, Port: 1234},
					},
				},
				Status: slim_corev1.ServiceStatus{
					LoadBalancer: slim_corev1.LoadBalancerStatus{
						Ingress: []slim_corev1.LoadBalancerIngress{
							{IP: "192.168.0.1"},
							{IP: "192.168.0.3"},
							{Hostname: "foo.bar.local"},
						},
					},
				},
			},
			expected: store.ClusterService{
				Name:            "foo",
				Namespace:       "bar",
				Shared:          true,
				IncludeExternal: false,
				Frontends: map[string]store.PortConfiguration{
					"192.168.0.1": {
						"http": &loadbalancer.L4Addr{
							Protocol: "TCP",
							Port:     1234,
						},
					},
					"192.168.0.3": {
						"http": &loadbalancer.L4Addr{
							Protocol: "TCP",
							Port:     1234,
						},
					},
				},
				Backends:  map[string]store.PortConfiguration{},
				Hostnames: map[string]string{},
				Labels:    map[string]string{},
				Zones:     map[string]store.BackendZone{},
				Selector:  map[string]string{},
			},
		},
		{
			name: "Headless phantom",
			svc: slim_corev1.Service{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:        "foo",
					Namespace:   "bar",
					Annotations: map[string]string{"service.isovalent.com/phantom": "true"},
				},
				Spec: slim_corev1.ServiceSpec{
					ClusterIP: "127.0.0.1",
					Type:      slim_corev1.ServiceTypeLoadBalancer,
					Ports: []slim_corev1.ServicePort{
						{Name: "http", Protocol: slim_corev1.ProtocolTCP, Port: 1234},
					},
				},
				Status: slim_corev1.ServiceStatus{
					LoadBalancer: slim_corev1.LoadBalancerStatus{
						Ingress: []slim_corev1.LoadBalancerIngress{},
					},
				},
			},
			expected: store.ClusterService{
				Name:      "foo",
				Namespace: "bar",
			},
			deleted: true,
		},
		{
			name: "Non-phantom service",
			svc: slim_corev1.Service{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:        "foo",
					Namespace:   "bar",
					Annotations: map[string]string{"service.isovalent.com/phantom": "false"},
				},
			},
			expected: store.ClusterService{
				Name:      "foo",
				Namespace: "bar",
			},
			deleted: true,
		},
	}

	conv := phantomServiceConverter{watchers.DefaultClusterServiceConverter{}}
	getEndpoints := func(ns, name string) []*k8s.Endpoints {
		return nil
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, toUpsert := conv.Convert(&tt.svc, getEndpoints)
			require.Equal(t, &tt.expected, out)
			require.Equal(t, tt.deleted, !toUpsert)
		})
	}
}

func TestGetAnnotationPhantom(t *testing.T) {
	tests := []struct {
		name            string
		annotations     map[string]string
		svcType         slim_corev1.ServiceType
		expectedGlobal  bool
		expectedShared  bool
		expectedPhantom bool
	}{
		{
			name:    "LoadBalancer service without annotations",
			svcType: slim_corev1.ServiceTypeLoadBalancer,
		},
		{
			name:        "ClusterIP service, phantom annotation set",
			annotations: map[string]string{"service.isovalent.com/phantom": "true"},
			svcType:     slim_corev1.ServiceTypeClusterIP,
		},
		{
			name:        "LoadBalancer service, phantom annotation not set",
			annotations: map[string]string{"service.isovalent.com/phantom": "false"},
			svcType:     slim_corev1.ServiceTypeLoadBalancer,
		},
		{
			name:            "LoadBalancer service, phantom annotation set (lowercase)",
			annotations:     map[string]string{"service.isovalent.com/phantom": "true"},
			svcType:         slim_corev1.ServiceTypeLoadBalancer,
			expectedPhantom: true,
		},
		{
			name:            "LoadBalancer service, phantom annotation set (uppercase)",
			annotations:     map[string]string{"service.isovalent.com/phantom": "TRUE"},
			svcType:         slim_corev1.ServiceTypeLoadBalancer,
			expectedPhantom: true,
		},
		{
			name:           "LoadBalancer service, both global and phantom annotations set",
			annotations:    map[string]string{"service.cilium.io/global": "true", "service.isovalent.com/phantom": "true"},
			svcType:        slim_corev1.ServiceTypeLoadBalancer,
			expectedGlobal: true, // The global service annotation takes precedence over the phantom service one.
			expectedShared: true, // A global service is shared by default if not otherwise specified.
		},
		{
			name:           "LoadBalancer service, global annotation set, phantom annotation unset",
			annotations:    map[string]string{"service.cilium.io/global": "true", "service.isovalent.com/phantom": "false"},
			svcType:        slim_corev1.ServiceTypeLoadBalancer,
			expectedGlobal: true,
			expectedShared: true,
		},
		{
			name:        "LoadBalancer service, shared annotation set, phantom annotation unset",
			annotations: map[string]string{"service.cilium.io/shared": "true", "service.isovalent.com/phantom": "false"},
			svcType:     slim_corev1.ServiceTypeLoadBalancer,
		},
		{
			name:            "LoadBalancer service, both shared and phantom annotations set",
			annotations:     map[string]string{"service.cilium.io/shared": "true", "service.isovalent.com/phantom": "true"},
			svcType:         slim_corev1.ServiceTypeLoadBalancer,
			expectedPhantom: true, // The shared service annotation does not affect the phantom service one.
		},
		{
			name:            "LoadBalancer service, shared annotation unset, phantom annotation set",
			annotations:     map[string]string{"service.cilium.io/shared": "false", "service.isovalent.com/phantom": "true"},
			svcType:         slim_corev1.ServiceTypeLoadBalancer,
			expectedPhantom: true, // The shared service annotation does not affect the phantom service one.
		},
		{
			name: "LoadBalancer service, global + shared + phantom annotations set",
			annotations: map[string]string{
				"service.cilium.io/global":      "true",
				"service.cilium.io/shared":      "true",
				"service.isovalent.com/phantom": "true",
			},
			svcType:        slim_corev1.ServiceTypeLoadBalancer,
			expectedGlobal: true, // The global service annotation takes precedence over the phantom service one.
			expectedShared: true,
		},
		{
			name: "LoadBalancer service, global annotation set, shared annotation unset, phantom annotation set",
			annotations: map[string]string{
				"service.cilium.io/global":      "true",
				"service.cilium.io/shared":      "false",
				"service.isovalent.com/phantom": "true",
			},
			svcType:        slim_corev1.ServiceTypeLoadBalancer,
			expectedGlobal: true, // The global service annotation takes precedence over the phantom service one.
			expectedShared: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := slim_corev1.Service{
				ObjectMeta: slim_metav1.ObjectMeta{Annotations: tt.annotations},
				Spec:       slim_corev1.ServiceSpec{Type: tt.svcType},
			}

			assert.Equal(t, tt.expectedGlobal, annotation.GetAnnotationIncludeExternal(&svc), "Incorrect global service detection")
			assert.Equal(t, tt.expectedShared, annotation.GetAnnotationShared(&svc), "Incorrect shared service detection")
			assert.Equal(t, tt.expectedPhantom, getAnnotationPhantom(&svc), "Incorrect phantom service detection")
		})
	}
}
