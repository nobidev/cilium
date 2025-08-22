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

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/operator/option"
	daemonOption "github.com/cilium/cilium/pkg/option"
)

type mockEnterpriseFeatures struct {
	EnterpriseBGPEnabled bool
}

func (p mockEnterpriseFeatures) IsEnterpriseBGPEnabled() bool {
	return p.EnterpriseBGPEnabled
}

func TestUpdateEnterpriseBGPEnabled(t *testing.T) {
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
			config := &option.OperatorConfig{}
			daemonConfig := &daemonOption.DaemonConfig{}

			params := mockEnterpriseFeatures{
				EnterpriseBGPEnabled: tt.enableEnterpriseBGP,
			}

			metrics.update(params, config, daemonConfig)

			counterValue := metrics.ACLBEnterpriseBGPEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableEnterpriseBGP, counterValue)
		})
	}
}
