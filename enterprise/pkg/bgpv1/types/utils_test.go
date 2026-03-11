// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseCommunity(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  uint32
		expectErr bool
	}{
		{
			name:     "asn value pair",
			input:    "65000:100",
			expected: NewCommunity(65000, 100),
		},
		{
			name:     "max asn value pair",
			input:    "65535:65535",
			expected: NewCommunity(65535, 65535),
		},
		{
			name:     "single decimal",
			input:    "4294967295",
			expected: ^uint32(0),
		},
		{
			name:      "empty string",
			input:     "",
			expectErr: true,
		},
		{
			name:      "non numeric",
			input:     "foo",
			expectErr: true,
		},
		{
			name:      "missing second component",
			input:     "65000:",
			expectErr: true,
		},
		{
			name:      "missing first component",
			input:     ":100",
			expectErr: true,
		},
		{
			name:      "too many components",
			input:     "65000:100:1",
			expectErr: true,
		},
		{
			name:      "negative decimal",
			input:     "-1",
			expectErr: true,
		},
		{
			name:      "asn overflow",
			input:     "65536:1",
			expectErr: true,
		},
		{
			name:      "value overflow",
			input:     "1:65536",
			expectErr: true,
		},
		{
			name:      "decimal overflow",
			input:     "4294967296",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			community, err := ParseCommunity(tt.input)
			if tt.expectErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expected, community)
		})
	}
}
