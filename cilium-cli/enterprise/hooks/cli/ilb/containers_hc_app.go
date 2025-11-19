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
	"fmt"
	"strings"
)

type hcAppContainer struct {
	dockerContainer
	config backendApplicationConfig
}

type backendApplicationConfig struct {
	h2cEnabled        bool
	tlsCertHostname   string
	listenPort        uint32
	healthCheckPort   uint32
	controlListenPort uint32
	image             string
	envVars           map[string]string
}

type hcState string

const (
	hcFail hcState = "fail"
	hcOK   hcState = "ok"
)

func (c *hcAppContainer) SetHC(t T, hc hcState) {
	scheme := "http"
	options := "--silent -XPOST"

	cmd := fmt.Sprintf(
		"curl %s %s://127.0.0.1:%d/control/healthcheck/"+string(hc),
		options, scheme, c.config.controlListenPort,
	)

	t.Log("Executing command on container %q: %q", c.id, cmd)
	stdout, stderr, err := c.Exec(t.Context(), cmd)
	if err != nil {
		t.Failedf("failed to set hc status to %s: stdout: %s stderr: %s err: %v",
			string(hc), stdout, stderr, err)
	}

	state := "false"
	if hc == hcOK {
		state = "true"
	}
	if strings.TrimSpace(stdout) != "healthcheck OK: "+state {
		t.Failedf("expected different output, got %q", stdout)
	}
}
