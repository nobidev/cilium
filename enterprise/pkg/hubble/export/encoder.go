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
	"encoding/json"
	"errors"
	"io"

	"github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/hubble/exporter"
)

var _ exporter.Encoder = (*enterpriseJsonEncoder)(nil)

type enterpriseJsonEncoder struct {
	enc *json.Encoder

	useFormatVersionV1 bool
	nodeName           string
}

func newJsonEncoderFromStaticConfig(conf config, writer io.Writer) *enterpriseJsonEncoder {
	return &enterpriseJsonEncoder{
		enc:                json.NewEncoder(writer),
		useFormatVersionV1: conf.FormatVersion == formatVersionV1,
		nodeName:           conf.NodeName,
	}
}

func newJsonEncoderFromDynamicConfig(conf *FlowLogConfig, writer io.Writer) *enterpriseJsonEncoder {
	return &enterpriseJsonEncoder{
		enc:                json.NewEncoder(writer),
		useFormatVersionV1: conf.FormatVersion == formatVersionV1,
		nodeName:           conf.NodeName,
	}
}

// Encode implements the exporter.Encoder interface.
func (e *enterpriseJsonEncoder) Encode(v any) error {
	if ev, ok := v.(*observerpb.ExportEvent); ok {
		if rt, ok := ev.ResponseTypes.(*observerpb.ExportEvent_Flow); ok {
			return e.encodeFlow(rt.Flow)
		}
	}
	if ev, ok := v.(*RateLimitInfoEvent); ok {
		return e.enc.Encode(ev)
	}
	return errors.New("unsupported type")
}

func (e *enterpriseJsonEncoder) encodeFlow(flow *flow.Flow) error {
	if e.nodeName != "" {
		flow.NodeName = e.nodeName
	}
	if e.useFormatVersionV1 {
		return e.enc.Encode(&observerpb.GetFlowsResponse{
			ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: flow},
			NodeName:      flow.NodeName,
			Time:          flow.Time,
		})
	}
	return e.enc.Encode(flow)
}
