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
