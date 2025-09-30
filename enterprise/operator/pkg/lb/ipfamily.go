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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func getServiceIPFamilies(family ipFamily) []corev1.IPFamily {
	switch family {
	case ipFamilyDual:
		return []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol}
	case ipFamilyV4:
		return []corev1.IPFamily{corev1.IPv4Protocol}
	case ipFamilyV6:
		return []corev1.IPFamily{corev1.IPv6Protocol}
	default:
		return []corev1.IPFamily{corev1.IPv4Protocol}
	}
}

func getServiceIPFamilyPolicy(family ipFamily) *corev1.IPFamilyPolicy {
	switch family {
	case ipFamilyDual:
		return ptr.To(corev1.IPFamilyPolicyRequireDualStack)
	case ipFamilyV4:
		return ptr.To(corev1.IPFamilyPolicySingleStack)
	case ipFamilyV6:
		return ptr.To(corev1.IPFamilyPolicySingleStack)
	default:
		return ptr.To(corev1.IPFamilyPolicySingleStack)
	}
}

func getIPFamily(vip *isovalentv1alpha1.LBVIP) ipFamily {
	if vip == nil {
		return ipFamilyV4
	}

	if vip.Spec.AddressFamily == nil {
		return ipFamilyV4
	}

	switch *vip.Spec.AddressFamily {
	case isovalentv1alpha1.AddressFamilyIPv4:
		return ipFamilyV4
	case isovalentv1alpha1.AddressFamilyIPv6:
		return ipFamilyV6
	case isovalentv1alpha1.AddressFamilyDual:
		return ipFamilyDual
	}

	return ipFamilyV4
}
