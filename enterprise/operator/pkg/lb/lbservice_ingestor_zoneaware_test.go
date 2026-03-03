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

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestIngestorResolveZoneAwareMode(t *testing.T) {
	ing := &ingestor{}

	testCases := []struct {
		name   string
		lbsvc  *isovalentv1alpha1.LBService
		expect lbServiceZoneAwareModeType
	}{
		{
			name:   "defaults to disabled when traffic policy is unset",
			lbsvc:  &isovalentv1alpha1.LBService{},
			expect: lbServiceZoneAwareModeDisabled,
		},
		{
			name: "maps preferSameZone from spec",
			lbsvc: &isovalentv1alpha1.LBService{
				Spec: isovalentv1alpha1.LBServiceSpec{
					TrafficPolicy: &isovalentv1alpha1.LBTrafficPolicy{
						ZoneAware: &isovalentv1alpha1.LBZoneAware{Mode: isovalentv1alpha1.LBZoneAwareModePreferSameZone},
					},
				},
			},
			expect: lbServiceZoneAwareModePreferSameZone,
		},
		{
			name: "maps requireSameZone from spec",
			lbsvc: &isovalentv1alpha1.LBService{
				Spec: isovalentv1alpha1.LBServiceSpec{
					TrafficPolicy: &isovalentv1alpha1.LBTrafficPolicy{
						ZoneAware: &isovalentv1alpha1.LBZoneAware{Mode: isovalentv1alpha1.LBZoneAwareModeRequireSameZone},
					},
				},
			},
			expect: lbServiceZoneAwareModeRequireSameZone,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expect, ing.resolveZoneAwareMode(tc.lbsvc))
		})
	}
}

func TestResolveNodeZone(t *testing.T) {
	testCases := []struct {
		name       string
		nodeLabels map[string]string
		expect     string
	}{
		{
			name: "use kubernetes topology zone label",
			nodeLabels: map[string]string{
				corev1.LabelTopologyZone: "zone-k8s",
			},
			expect: "zone-k8s",
		},
		{
			name:       "returns unknown when labels are missing",
			nodeLabels: map[string]string{},
			expect:     lbServiceZoneUnknown,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expect, resolveNodeZone(tc.nodeLabels))
		})
	}
}
