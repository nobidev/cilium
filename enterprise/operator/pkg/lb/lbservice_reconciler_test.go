//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lb

import (
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestGetIncompatibleT1HealthCheckBackends(t *testing.T) {
	r := lbServiceReconciler{}
	tcpProxyT1Mode := isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1
	udpProxyT1Mode := isovalentv1alpha1.LBUDPProxyForceDeploymentModeT1
	customPort := int32(8080)

	testCases := []struct {
		desc     string
		lbsvc    *isovalentv1alpha1.LBService
		backends []*isovalentv1alpha1.LBBackendPool
		expected []string
	}{
		{
			desc: "No incompatible TCPProxy backends",
			lbsvc: &isovalentv1alpha1.LBService{
				Spec: isovalentv1alpha1.LBServiceSpec{
					Applications: isovalentv1alpha1.LBServiceApplications{
						TCPProxy: &isovalentv1alpha1.LBServiceApplicationTCPProxy{
							ForceDeploymentMode: &tcpProxyT1Mode,
							Routes: []isovalentv1alpha1.LBServiceTCPRoute{
								{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
								{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-2"}},
							},
						},
					},
				},
			},
			backends: []*isovalentv1alpha1.LBBackendPool{
				{ObjectMeta: v1.ObjectMeta{Name: "backend-1"}},
				{ObjectMeta: v1.ObjectMeta{Name: "backend-2"}},
			},
			expected: []string{},
		},
		{
			desc: "Incompatible TCPProxy backends with custom port",
			lbsvc: &isovalentv1alpha1.LBService{
				Spec: isovalentv1alpha1.LBServiceSpec{
					Applications: isovalentv1alpha1.LBServiceApplications{
						TCPProxy: &isovalentv1alpha1.LBServiceApplicationTCPProxy{
							ForceDeploymentMode: &tcpProxyT1Mode,
							Routes: []isovalentv1alpha1.LBServiceTCPRoute{
								{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
								{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-2"}},
							},
						},
					},
				},
			},
			backends: []*isovalentv1alpha1.LBBackendPool{
				{
					ObjectMeta: v1.ObjectMeta{Name: "backend-1"},
					Spec: isovalentv1alpha1.LBBackendPoolSpec{
						HealthCheck: isovalentv1alpha1.HealthCheck{Port: &customPort},
					},
				},
				{
					ObjectMeta: v1.ObjectMeta{Name: "backend-2"},
					Spec: isovalentv1alpha1.LBBackendPoolSpec{
						HealthCheck: isovalentv1alpha1.HealthCheck{Port: &customPort},
					},
				},
			},
			expected: []string{"forceDeploymentMode t1-only is incompatible with LBBackendPools that configure an explicit health check port [backend-1 backend-2]"},
		},
		{
			desc: "No incompatible UDPProxy backends",
			lbsvc: &isovalentv1alpha1.LBService{
				Spec: isovalentv1alpha1.LBServiceSpec{
					Applications: isovalentv1alpha1.LBServiceApplications{
						UDPProxy: &isovalentv1alpha1.LBServiceApplicationUDPProxy{
							ForceDeploymentMode: &udpProxyT1Mode,
							Routes: []isovalentv1alpha1.LBServiceUDPRoute{
								{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
								{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-2"}},
							},
						},
					},
				},
			},
			backends: []*isovalentv1alpha1.LBBackendPool{
				{ObjectMeta: v1.ObjectMeta{Name: "backend-1"}},
				{ObjectMeta: v1.ObjectMeta{Name: "backend-2"}},
			},
			expected: []string{},
		},
		{
			desc: "Incompatible UDPProxy backends with custom port",
			lbsvc: &isovalentv1alpha1.LBService{
				Spec: isovalentv1alpha1.LBServiceSpec{
					Applications: isovalentv1alpha1.LBServiceApplications{
						UDPProxy: &isovalentv1alpha1.LBServiceApplicationUDPProxy{
							ForceDeploymentMode: &udpProxyT1Mode,
							Routes: []isovalentv1alpha1.LBServiceUDPRoute{
								{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-1"}},
								{BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: "backend-2"}},
							},
						},
					},
				},
			},
			backends: []*isovalentv1alpha1.LBBackendPool{
				{
					ObjectMeta: v1.ObjectMeta{Name: "backend-1"},
					Spec: isovalentv1alpha1.LBBackendPoolSpec{
						HealthCheck: isovalentv1alpha1.HealthCheck{Port: &customPort},
					},
				},
				{
					ObjectMeta: v1.ObjectMeta{Name: "backend-2"},
					Spec: isovalentv1alpha1.LBBackendPoolSpec{
						HealthCheck: isovalentv1alpha1.HealthCheck{Port: &customPort},
					},
				},
			},
			expected: []string{"forceDeploymentMode t1-only is incompatible with LBBackendPools that configure an explicit health check port [backend-1 backend-2]"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			actual := r.getIncompatibleT1HealthCheckBackends(tc.lbsvc, tc.backends)

			assert.Equal(t, tc.expected, actual)
		})
	}
}
