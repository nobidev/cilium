//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import (
	"encoding/json"
	"testing"
)

type testAppResponseData struct {
	ServiceName  string `json:"service_name"`
	InstanceName string `json:"instance_name"`
	RequestPath  string `json:"request_path"`
	StatusCode   int    `json:"status_code"`
	StatusText   string `json:"status_text"`
	HealthStatus string `json:"health_status"`
	RemoteAddr   string `json:"remote_addr"`
	RequestID    string `json:"x_request_id"`
	XFF          string `json:"x_forwarded_for"`
}

func toTestAppResponse(t *testing.T, response string) testAppResponseData {
	resp := testAppResponseData{}

	if err := json.Unmarshal([]byte(response), &resp); err != nil {
		t.Fatalf("parsing test app response failed (stdout: %q): %s", response, err)
	}

	return resp
}
