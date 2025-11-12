// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package privnet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"

	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type clientToEcho struct {
	scenario

	src VM
	dst VM
}

func NewClientToEcho(t *TestRun, src, dst VM) Scenario {
	name := fmt.Sprintf("curl-%s-to-%s", src.Name, dst.Name)
	return &clientToEcho{
		scenario: scenario{t: t, name: name},
		src:      src,
		dst:      dst,
	}
}

func (s *clientToEcho) Run(ctx context.Context, exp Expectation, overrideIPFamilies ...features.IPFamily) {
	for family := range s.t.theFamilies(overrideIPFamilies...) {
		s.run(ctx, exp, family)
	}
}

func (s *clientToEcho) run(ctx context.Context, exp Expectation, family features.IPFamily) {
	var stdout, stderr bytes.Buffer
	dstIP := s.dst.IP(family)
	srcIP := s.src.IP(family)

	s.t.log.Info(fmt.Sprintf("🧐 Executing curl %s (%v) %s %s (%v:%v)", s.src.Name, srcIP, exp, s.dst.Name, dstIP, EchoServerPort))
	err := s.t.client.ExecInVMWithWriters(ctx, s.t.params.TestNamespace, s.src.Name.String(),
		curlCmd(netip.AddrPortFrom(dstIP, EchoServerPort).String()),
		&stdout, &stderr)

	exitCode, ok := extractExitCode(err)
	if !ok {
		s.fail(family, "failed with unexpected exec error: %s", err)
		return
	} else if exitCode != exp.ExitStatus {
		s.t.log.Debug("curl output",
			logfields.Stdout, stdout,
			logfields.Stderr, stderr,
		)
		s.fail(family, "unexpected curl exit code. got %d want %d", exitCode, exp.ExitStatus)
		return
	}

	if exitCode != 0 {
		// curl failed as expected, return early as we will have no expected output
		return
	}

	response := map[string]string{}
	err = json.Unmarshal(stdout.Bytes(), &response)
	if err != nil {
		s.fail(family, "failed to parse echo server response %q: %s", stdout.String(), err)
		return
	}

	expected := map[string]string{
		"network":   s.dst.NetName.String(),
		"client-ip": srcIP.String(),
	}
	if !maps.Equal(response, expected) {
		s.fail(family, "unexpected response. got %+v, want %+v", response, expected)
	}
}
