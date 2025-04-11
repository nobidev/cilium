// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package export

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/hubble/exporter"
)

func TestCompareEnterpriseFlowLogConfig(t *testing.T) {
	cases := []struct {
		name          string
		currentConfig *EnterpriseFlowLogConfig
		newConfig     *EnterpriseFlowLogConfig
		expectEqual   bool
	}{
		{
			name:          "should equal for same FileRotationInterval",
			currentConfig: &EnterpriseFlowLogConfig{FileRotationInterval: durationPtr(time.Second)},
			newConfig:     &EnterpriseFlowLogConfig{FileRotationInterval: durationPtr(time.Second)},
			expectEqual:   true,
		},
		{
			name:          "should equal for same FormatVersion",
			currentConfig: &EnterpriseFlowLogConfig{FormatVersion: formatVersionV1},
			newConfig:     &EnterpriseFlowLogConfig{FormatVersion: formatVersionV1},
			expectEqual:   true,
		},
		{
			name:          "should equal for same RateLimit",
			currentConfig: &EnterpriseFlowLogConfig{RateLimit: intPtr(10)},
			newConfig:     &EnterpriseFlowLogConfig{RateLimit: intPtr(10)},
			expectEqual:   true,
		},
		{
			name:          "should equal for same RateNodeNameLimit",
			currentConfig: &EnterpriseFlowLogConfig{NodeName: "my-node"},
			newConfig:     &EnterpriseFlowLogConfig{NodeName: "my-node"},
			expectEqual:   true,
		},
		{
			name:          "should equal for same Aggregations",
			currentConfig: &EnterpriseFlowLogConfig{Aggregations: []string{"identity"}},
			newConfig:     &EnterpriseFlowLogConfig{Aggregations: []string{"identity"}},
			expectEqual:   true,
		},
		{
			name:          "should equal for same AggregationIgnoreSourcePort",
			currentConfig: &EnterpriseFlowLogConfig{AggregationIgnoreSourcePort: true},
			newConfig:     &EnterpriseFlowLogConfig{AggregationIgnoreSourcePort: true},
			expectEqual:   true,
		},
		{
			name:          "should equal for same AggregationRenewTTL",
			currentConfig: &EnterpriseFlowLogConfig{AggregationRenewTTL: true},
			newConfig:     &EnterpriseFlowLogConfig{AggregationRenewTTL: true},
			expectEqual:   true,
		},
		{
			name:          "should equal for same AggregationStateChangeFilter",
			currentConfig: &EnterpriseFlowLogConfig{AggregationStateChangeFilter: []string{"new", "error"}},
			newConfig:     &EnterpriseFlowLogConfig{AggregationStateChangeFilter: []string{"new", "error"}},
			expectEqual:   true,
		},
		{
			name:          "should equal for same AggregationTTL",
			currentConfig: &EnterpriseFlowLogConfig{AggregationTTL: durationPtr(time.Second)},
			newConfig:     &EnterpriseFlowLogConfig{AggregationTTL: durationPtr(time.Second)},
			expectEqual:   true,
		},
		{
			name:          "should not equal if Aggregations same length",
			currentConfig: &EnterpriseFlowLogConfig{Aggregations: []string{"identity"}},
			newConfig:     &EnterpriseFlowLogConfig{Aggregations: []string{"connection"}},
			expectEqual:   false,
		},
		{
			name:          "should not equal if AggregationStateChangeFilter same length",
			currentConfig: &EnterpriseFlowLogConfig{AggregationStateChangeFilter: []string{"new", "error"}},
			newConfig:     &EnterpriseFlowLogConfig{AggregationStateChangeFilter: []string{"established", "close"}},
			expectEqual:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.currentConfig.equals(tc.newConfig)
			assert.Equal(t, tc.expectEqual, result)
		})
	}
}

func TestParseEnterpriseDynamicExportersConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		want    map[string]exporter.ExporterConfig
		wantErr bool
	}{
		{
			name:   "empty",
			config: "",
			want:   map[string]exporter.ExporterConfig{},
		},
		{
			name: "complete",
			config: `
                flowLogs:
                  - name: all
                    filePath: /var/run/cilium/hubble/hubble.log
                    fileMaxSizeMb: 10
                    fileMaxBackups: 5
                    fileCompress: true
                    fileRotationInterval: 1m
                    formatVersion: ""
                    nodeName: my-node
                    rateLimit: 10
                    aggregation:
                      - identity
                    aggregationIgnoreSourcePort: true
                    aggregationRenewTTL: true
                    aggregationStateFilter:
                      - new
                      - error
                    aggregationTTL: 30s
            `,
			want: map[string]exporter.ExporterConfig{
				"all": &EnterpriseFlowLogConfig{
					// exporter.FlowLogConfig already has tests, no need to re-test parsing here
					FlowLogConfig: exporter.FlowLogConfig{
						Name:           "all",
						FilePath:       "/var/run/cilium/hubble/hubble.log",
						FileMaxSizeMB:  10,
						FileMaxBackups: 5,
						FileCompress:   true,
					},
					FileRotationInterval:         durationPtr(time.Minute),
					FormatVersion:                "",
					NodeName:                     "my-node",
					RateLimit:                    intPtr(10),
					Aggregations:                 []string{"identity"},
					AggregationIgnoreSourcePort:  true,
					AggregationRenewTTL:          true,
					AggregationStateChangeFilter: []string{"new", "error"},
					AggregationTTL:               durationPtr(30 * time.Second),
				},
			},
		},
		{
			name: "missing required name",
			config: `
                flowLogs:
                  - filePath: /var/run/cilium/hubble/hubble.log
            `,
			wantErr: true,
		},
		{
			name: "missing required filepath",
			config: `
                flowLogs:
                  - name: all
            `,
			wantErr: true,
		},
		{
			name: "duplicated name",
			config: `
                flowLogs:
                  - name: all
                  - name: all
            `,
			wantErr: true,
		},
		{
			name: "duplicated filepath",
			config: `
                flowLogs:
                  - filePath: /var/run/cilium/hubble/hubble.log
                  - filePath: /var/run/cilium/hubble/hubble.log
            `,
			wantErr: true,
		},
	}

	configParser := exporterConfigParser{logger: slog.Default()}

	for i, test := range tests {
		t.Run(fmt.Sprintf("%d. %s", i, t.Name()), func(t *testing.T) {
			got, err := configParser.Parse(strings.NewReader(test.config))
			if test.wantErr {
				assert.Error(t, err)
				return
			}
			if assert.NoError(t, err) {
				assert.Equal(t, test.want, got)
			}
		})
	}
}

func durationPtr(d time.Duration) *Duration {
	dd := Duration(d)
	return &dd
}

func intPtr(i int) *int {
	return &i
}
