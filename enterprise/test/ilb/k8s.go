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
	v1 "k8s.io/api/core/v1"
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

func lbServiceApplicationsHTTPSProxy(backendRef, secretName, hostName string) isovalentv1alpha1.LBServiceApplications {
	return isovalentv1alpha1.LBServiceApplications{
		HTTPSProxy: &isovalentv1alpha1.LBServiceApplicationHTTPSProxy{
			TLSConfig: &isovalentv1alpha1.LBServiceTLSConfig{
				Certificates: []isovalentv1alpha1.LBServiceTLSCertificate{
					{SecretRef: isovalentv1alpha1.LBServiceSecretRef{Name: secretName}},
				},
			},
			Routes: []isovalentv1alpha1.LBServiceHTTPRoute{
				{
					BackendRef: isovalentv1alpha1.LBServiceBackendRef{Name: backendRef},
					Match: &isovalentv1alpha1.LBServiceHTTPRouteMatch{
						HostNames: []isovalentv1alpha1.LBServiceHostName{
							isovalentv1alpha1.LBServiceHostName(hostName),
						},
					},
				},
			},
		},
	}
}

func lbServiceApplicationsHTTP(backendRef, hostName string) isovalentv1alpha1.LBServiceApplications {
	obj := isovalentv1alpha1.LBServiceApplications{
		HTTPProxy: &isovalentv1alpha1.LBServiceApplicationHTTPProxy{
			Routes: []isovalentv1alpha1.LBServiceHTTPRoute{
				{BackendRef: isovalentv1alpha1.LBServiceBackendRef{
					Name: backendRef,
				},
				},
			},
		},
	}

	if hostName != "" {
		obj.HTTPProxy.Routes[0].Match = &isovalentv1alpha1.LBServiceHTTPRouteMatch{
			HostNames: []isovalentv1alpha1.LBServiceHostName{isovalentv1alpha1.LBServiceHostName(hostName)},
		}

	}

	return obj
}

func lbService(name, vipRefName string, port int32, app isovalentv1alpha1.LBServiceApplications) *isovalentv1alpha1.LBService {
	return &isovalentv1alpha1.LBService{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: isovalentv1alpha1.LBServiceSpec{
			VIPRef: isovalentv1alpha1.LBServiceVIPRef{
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

func bgpPeeringPolicy(name string) *ciliumv2alpha1.CiliumBGPPeeringPolicy {
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
						// Create a dummy neighbor until we switch to BGPv2
						{PeerAddress: "0.0.0.0/0"},
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

func secret(name string, key, cert []byte) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Type: v1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.key": key,
			"tls.crt": cert,
		},
	}
}
