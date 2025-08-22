//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package features

import (
	"testing"

	"github.com/cilium/cilium/pkg/option"

	"github.com/stretchr/testify/assert"
)

type mockEnterpriseFeatures struct {
	EnterpriseBGPEnabled bool
	BFDEnabled           bool
}

func (m mockEnterpriseFeatures) IsEnterpriseBGPEnabled() bool {
	return m.EnterpriseBGPEnabled
}

func (m mockEnterpriseFeatures) IsBFDEnabled() bool {
	return m.BFDEnabled
}

func TestUpdateSRv6(t *testing.T) {
	tests := []struct {
		name       string
		enableSRv6 bool
		expected   float64
	}{
		{
			name:       "SRv6 enabled",
			enableSRv6: true,
			expected:   1,
		},
		{
			name:       "SRv6 disabled",
			enableSRv6: false,
			expected:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewEnterpriseMetrics(true)
			config := &option.DaemonConfig{
				EnableSRv6: tt.enableSRv6,
			}

			params := mockEnterpriseFeatures{}

			metrics.update(params, config)

			counterValue := metrics.ACLBSRv6.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableSRv6, counterValue)
		})
	}
}

func TestUpdateEnterpriseBGP(t *testing.T) {
	tests := []struct {
		name                string
		enableEnterpriseBGP bool
		expected            float64
	}{
		{
			name:                "Enterprise BGP enabled",
			enableEnterpriseBGP: true,
			expected:            1,
		},
		{
			name:                "Enterprise BGP disabled",
			enableEnterpriseBGP: false,
			expected:            0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewEnterpriseMetrics(true)
			config := &option.DaemonConfig{}

			params := mockEnterpriseFeatures{
				EnterpriseBGPEnabled: tt.enableEnterpriseBGP,
			}

			metrics.update(params, config)

			counterValue := metrics.ACLBEnterpriseBGPEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableEnterpriseBGP, counterValue)
		})
	}
}

func TestUpdateBFD(t *testing.T) {
	tests := []struct {
		name      string
		enableBFD bool
		expected  float64
	}{
		{
			name:      "BFD enabled",
			enableBFD: true,
			expected:  1,
		},
		{
			name:      "BFD disabled",
			enableBFD: false,
			expected:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewEnterpriseMetrics(true)
			config := &option.DaemonConfig{}

			params := mockEnterpriseFeatures{
				BFDEnabled: tt.enableBFD,
			}

			metrics.update(params, config)

			counterValue := metrics.ACLBBFDEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableBFD, counterValue)
		})
	}
}
