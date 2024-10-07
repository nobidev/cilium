// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this
// information or reproduction of this material is strictly forbidden unless
// prior written permission is obtained from Isovalent Inc.

//go:build enterprise_integrated_timescape_e2e

package integrated_timescape

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	enthelpers "github.com/cilium/cilium/enterprise/test/helpers"
	"github.com/cilium/cilium/test/helpers"

	fakeflow "github.com/cilium/fake/flow"
	"github.com/stretchr/testify/require"
)

func hubbleObserve(t *testing.T, ctx context.Context, extraArgs ...string) string {
	t.Helper()
	args := append(
		[]string{"observe", "-o", "json"},
		extraArgs...,
	)
	if strings.ToLower(os.Getenv("TEST_HUBBLE_OBSERVE_TLS")) == "true" {
		args = append(args, "--tls", "--tls-allow-insecure")
	}
	out, err := enthelpers.HubbleCLI(ctx, args...)
	require.NoError(t, err)
	return out
}

func TestHubbleObserve(t *testing.T) {
	ctx := context.Background()

	out := hubbleObserve(t, ctx)
	flows := enthelpers.GetFlowsResponseFromReader(t, strings.NewReader(out))
	require.NotEmpty(t, flows, "expected flows to be returned")
}

func TestPushFlows(t *testing.T) {
	now := time.Now()
	ctx := context.Background()
	// Generate some fake flow data to push to timescape
	nodeName := fmt.Sprintf("integrated-ts-test-node-%d", now.Unix())
	t.Log("using node name", nodeName) // log for troubleshooting
	inputFlows := genFakeExportFlows(t, 4, now, nodeName)
	flowBuf := encodeGetFlowsResponse(t, inputFlows)

	// Push the flows
	http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost:4260/push", flowBuf)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost:4260/push", flowBuf)
	require.NoError(t, err, "Should succeed creating request")
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, err, "Should succeed pushing flows to timescape push API")
	res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode, "Should succeed pushing flows to timescape push API")

	// Query the flows back so we can verify they have been stored
	out := hubbleObserve(t, ctx, "--node-name", nodeName)
	gotFlows := enthelpers.GetFlowsResponseFromReader(t, strings.NewReader(out))
	helpers.AssertProtoEqual(t, inputFlows, gotFlows)

}

func encodeGetFlowsResponse(t *testing.T, flows []*observerpb.GetFlowsResponse) io.Reader {
	t.Helper()
	var buf bytes.Buffer
	flowEn := json.NewEncoder(&buf)
	for _, flow := range flows {
		err := flowEn.Encode(flow)
		require.NoError(t, err)
	}
	return &buf
}

func genFakeExportFlows(t *testing.T, count int, baseTime time.Time, nodeName string) []*observerpb.GetFlowsResponse {
	t.Helper()
	flows := make([]*observerpb.GetFlowsResponse, 0, count)
	for i := range count {
		flow := fakeflow.New(
			// Use a specific NodeName for exported flows so we can query the flow
			fakeflow.WithFlowNodeName(nodeName),
			// ensure time is increasing so that results are pre-sorted by time
			fakeflow.WithFlowTime(baseTime.Add(time.Second*time.Duration(i))),
		)
		// Exported flows are wrapped in GetFlowsResponse
		resp := &observerpb.GetFlowsResponse{
			NodeName: flow.GetNodeName(),
			Time:     flow.GetTime(),
			ResponseTypes: &observerpb.GetFlowsResponse_Flow{
				Flow: flow,
			},
		}
		flows = append(flows, resp)
	}
	return flows
}
