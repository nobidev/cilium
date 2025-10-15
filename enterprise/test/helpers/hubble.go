// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this
// information or reproduction of this material is strictly forbidden unless
// prior written permission is obtained from Isovalent Inc.
package helpers

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"testing"

	observerpb "github.com/cilium/cilium/api/v1/observer"

	"github.com/stretchr/testify/require"
)

func HubbleCLI(ctx context.Context, args ...string) (string, error) {
	_, fname, _, _ := runtime.Caller(0)
	hubbleDir := path.Join(
		path.Dir(fname), "..", "..", "..", "enterprise", "hubble",
	)

	args = append([]string{"run", hubbleDir}, args...)
	cmd := exec.CommandContext(ctx, "go", args...)
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

func HubbleLogin(ctx context.Context, t *testing.T, username, password string) {
	t.Helper()
	require.NotEmpty(t, password, "no password provided")

	passwordFile, err := os.CreateTemp("", "")
	require.NoError(t, err)
	t.Cleanup(func() {
		passwordFile.Close()
		os.Remove(passwordFile.Name())
	})
	_, err = passwordFile.WriteString(password)
	require.NoError(t, err)

	loginArgs := []string{
		"login",
		"--debug",
		"--grant-type", "password",
		"--user", username,
		"--password-file", passwordFile.Name(),
		"--scopes", "email",
	}
	out, err := HubbleCLI(ctx, loginArgs...)
	require.NoError(t, err, out)
}

func GetFlowsResponseFromReader(t *testing.T, out io.Reader) []*observerpb.GetFlowsResponse {
	t.Helper()
	var flows []*observerpb.GetFlowsResponse
	dec := json.NewDecoder(out)
	for dec.More() {
		var flow observerpb.GetFlowsResponse
		err := dec.Decode(&flow)
		require.NoError(t, err)
		flows = append(flows, &flow)
	}
	return flows
}
