// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIncludeTenantLogLine(t *testing.T) {
	tests := []struct {
		name     string
		filters  []string
		logLine  string
		expected bool
	}{
		{
			name:     "no filters passes all lines",
			filters:  []string{},
			logLine:  "some random log line",
			expected: true,
		},
		{
			name:     "single matching filter",
			filters:  []string{"10.53.54.1"},
			logLine:  `downstream_remote_address:{socket_address:{address:"10.53.54.1" port_value:80}}`,
			expected: true,
		},
		{
			name:     "single non-matching filter",
			filters:  []string{"10.99.99.99"},
			logLine:  `downstream_remote_address:{socket_address:{address:"10.53.54.1" port_value:80}}`,
			expected: false,
		},
		{
			name:     "multiple filters all match",
			filters:  []string{"10.53.54.1", "port_value:80"},
			logLine:  `downstream_remote_address:{socket_address:{address:"10.53.54.1" port_value:80}}`,
			expected: true,
		},
		{
			name:     "multiple filters one misses",
			filters:  []string{"10.53.54.1", "port_value:443"},
			logLine:  `downstream_remote_address:{socket_address:{address:"10.53.54.1" port_value:80}}`,
			expected: false,
		},
		{
			name:     "empty log line with filters",
			filters:  []string{"something"},
			logLine:  "",
			expected: false,
		},
		{
			name:     "empty log line no filters",
			filters:  []string{},
			logLine:  "",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldFilters := accessLogGenericFilters
			defer func() { accessLogGenericFilters = oldFilters }()

			accessLogGenericFilters = tt.filters
			require.Equal(t, tt.expected, includeTenantLogLine(tt.logLine))
		})
	}
}

func TestAccesslogFlagValidation(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		expectErr string
	}{
		{
			name:      "since without tenant",
			args:      []string{"--since", "1h"},
			expectErr: "--since requires --tenant to be set",
		},
		{
			name:      "invalid since value",
			args:      []string{"--tenant", "tenant-a", "--since", "abc"},
			expectErr: `invalid --since value "abc"`,
		},
		{
			name:      "negative since value",
			args:      []string{"--tenant", "tenant-a", "--since", "-1h"},
			expectErr: "--since must be a positive duration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newCmdLoadbalancerT2AccesslogStreamer()
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			cmd.SetArgs(tt.args)

			err := cmd.Execute()

			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectErr)
		})
	}
}
