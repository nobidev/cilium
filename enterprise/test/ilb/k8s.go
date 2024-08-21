//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func lbIPPool(name, ipBlock string) *ciliumv2alpha1.CiliumLoadBalancerIPPool {
	return &ciliumv2alpha1.CiliumLoadBalancerIPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: ciliumv2alpha1.CiliumLoadBalancerIPPoolSpec{
			Blocks: []ciliumv2alpha1.CiliumLoadBalancerIPPoolIPBlock{
				{Cidr: ciliumv2alpha1.IPv4orIPv6CIDR(ipBlock)},
			},
		},
	}
}

func lbFrontendApplicationsHTTP(backendRef string) isovalentv1alpha1.LBFrontendApplications {
	return isovalentv1alpha1.LBFrontendApplications{
		HTTPProxy: &isovalentv1alpha1.LBFrontendApplicationHTTPProxy{
			Routes: []isovalentv1alpha1.LBFrontendHTTPRoute{
				{BackendRef: isovalentv1alpha1.LBFrontendBackendRef{
					Name: backendRef,
				},
				},
			},
		},
	}
}

func lbFrontend(name, vipRefName string, port int32, app isovalentv1alpha1.LBFrontendApplications) *isovalentv1alpha1.LBFrontend {
	return &isovalentv1alpha1.LBFrontend{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: isovalentv1alpha1.LBFrontendSpec{
			VIPRef: isovalentv1alpha1.LBFrontendVIPRef{
				Name: vipRefName,
			},
			Port:         port,
			Applications: app,
		},
	}
}

func lbBackendPool(name string, hcHTTPPath string, hcInterval int32, backends []isovalentv1alpha1.Backend) *isovalentv1alpha1.LBBackendPool {
	return &isovalentv1alpha1.LBBackendPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: isovalentv1alpha1.LBBackendPoolSpec{
			HealthCheck: isovalentv1alpha1.HealthCheck{
				IntervalSeconds: &hcInterval,
				HTTP: &isovalentv1alpha1.HealthCheckHTTP{
					Path: &hcHTTPPath,
				},
			},
			Backends: backends,
		},
	}

}

func lbVIP(name, ipv4Requested string) *isovalentv1alpha1.LBVIP {
	obj := &isovalentv1alpha1.LBVIP{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: isovalentv1alpha1.LBVIPSpec{},
	}
	if ipv4Requested != "" {
		obj.Spec.IPv4Request = &ipv4Requested
	}

	return obj
}

func bgpPeeringPolicy(name string, peerIPAddr string) *ciliumv2alpha1.CiliumBGPPeeringPolicy {
	obj := &ciliumv2alpha1.CiliumBGPPeeringPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: ciliumv2alpha1.CiliumBGPPeeringPolicySpec{
			NodeSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]slimv1.MatchLabelsValue{
					"service.cilium.io/node": "t1",
				},
			},
			VirtualRouters: []ciliumv2alpha1.CiliumBGPVirtualRouter{
				{
					LocalASN: 64512,
					ServiceSelector: &slimv1.LabelSelector{
						MatchExpressions: []slimv1.LabelSelectorRequirement{
							{
								Key:      "somekey",
								Operator: slimv1.LabelSelectorOpNotIn,
								Values:   []string{"never-used-value"},
							},
						},
					},
					Neighbors: []ciliumv2alpha1.CiliumBGPNeighbor{
						{
							PeerAddress:   peerIPAddr + "/32",
							PeerASN:       64512,
							BFDProfileRef: &name,
						},
					},
				},
			},
		},
	}

	return obj
}

func bfdProfile(name string) *isovalentv1alpha1.IsovalentBFDProfile {
	detectMultiplier := int32(3)
	receiveIntervalMilliseconds := int32(300)
	transmitIntervalMilliseconds := int32(300)

	return &isovalentv1alpha1.IsovalentBFDProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: isovalentv1alpha1.BFDProfileSpec{
			DetectMultiplier:             &detectMultiplier,
			ReceiveIntervalMilliseconds:  &receiveIntervalMilliseconds,
			TransmitIntervalMilliseconds: &transmitIntervalMilliseconds,
		},
	}
}
