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
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/time"
)

func TestEnterpriseJsonEncoderEncode(t *testing.T) {
	tests := []struct {
		name               string
		useFormatVersionV1 bool
		nodeName           string
		value              any
		want               string
		wantErr            bool
	}{
		{name: "unsupported type", value: "", wantErr: true},
		{
			name:    "unsupported non-flow ExportEvent",
			value:   &observerpb.ExportEvent{ResponseTypes: &observerpb.ExportEvent_AgentEvent{}},
			wantErr: true,
		},
		{
			name:               "RateLimitInfoEvent",
			useFormatVersionV1: false,
			value: &RateLimitInfoEvent{
				RateLimitInfo: &RateLimitInfo{NumberOfDroppedEvents: 1},
				NodeName:      "node-name",
				Time:          time.Time{},
			},
			want: `{"rate_limit_info": {"number_of_dropped_events": 1}, "node_name": "node-name", "time": "0001-01-01T00:00:00Z"}`,
		},
		{
			name:               "normal flow",
			useFormatVersionV1: false,
			value: &observerpb.ExportEvent{
				ResponseTypes: &observerpb.ExportEvent_Flow{
					Flow: &flow.Flow{
						NodeName: "node-name",
						Uuid:     "uuid",
						Time:     &timestamppb.Timestamp{},
					},
				},
			},
			want: `{"node_name": "node-name", "uuid": "uuid", "time": "1970-01-01T00:00:00Z"}`,
		},
		{
			name:               "overridden nodeName",
			useFormatVersionV1: false,
			nodeName:           "node-name",
			value: &observerpb.ExportEvent{
				ResponseTypes: &observerpb.ExportEvent_Flow{
					Flow: &flow.Flow{
						NodeName: "overridden",
						Uuid:     "uuid",
						Time:     &timestamppb.Timestamp{},
					},
				},
			},
			want: `{"node_name": "node-name", "uuid": "uuid", "time": "1970-01-01T00:00:00Z"}`,
		},
		{
			name:               "formatVersionV1",
			useFormatVersionV1: false,
			value: &observerpb.ExportEvent{
				ResponseTypes: &observerpb.ExportEvent_Flow{
					Flow: &flow.Flow{
						NodeName: "node-name",
						Uuid:     "uuid",
						Time:     &timestamppb.Timestamp{},
					},
				},
			},
			want: `{"node_name": "node-name", "uuid": "uuid", "time": "1970-01-01T00:00:00Z"}`,
		},
		{
			name:               "formatVersionV1 and overridden nodeName",
			useFormatVersionV1: false,
			nodeName:           "node-name",
			value: &observerpb.ExportEvent{
				ResponseTypes: &observerpb.ExportEvent_Flow{
					Flow: &flow.Flow{
						NodeName: "overridden",
						Uuid:     "uuid",
						Time:     &timestamppb.Timestamp{},
					},
				},
			},
			want: `{"node_name": "node-name", "uuid": "uuid", "time": "1970-01-01T00:00:00Z"}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buf bytes.Buffer
			encoder := &enterpriseJsonEncoder{
				enc:                json.NewEncoder(&buf),
				useFormatVersionV1: test.useFormatVersionV1,
				nodeName:           test.nodeName,
			}

			err := encoder.Encode(test.value)
			if test.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			assert.JSONEq(t, test.want, buf.String())
		})
	}
}
