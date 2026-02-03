//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lbflowlogs

import "testing"

func TestParseCollectorAddresses(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
		wantLen int
	}{
		{name: "empty", raw: "", wantErr: false, wantLen: 0},
		{name: "ipv4", raw: "10.0.0.1:4739", wantErr: false, wantLen: 1},
		{name: "ipv6", raw: "[2001:db8::1]:4739", wantErr: false, wantLen: 1},
		{name: "fqdn", raw: "collector.example.com:4739", wantErr: false, wantLen: 1},
		{name: "fqdn-trailing-dot", raw: "collector.example.com.:4739", wantErr: false, wantLen: 1},
		{name: "list", raw: "10.0.0.1:4739, [2001:db8::1]:4740", wantErr: false, wantLen: 2},
		{name: "list-whitespace", raw: " 10.0.0.1:4739 ,\tcollector.example.com:4740 ", wantErr: false, wantLen: 2},
		{name: "missing-port", raw: "10.0.0.1", wantErr: true},
		{name: "ipv6-without-brackets", raw: "2001:db8::1:4739", wantErr: true},
		{name: "empty-entry", raw: "10.0.0.1:4739,,collector.example.com:4740", wantErr: true},
		{name: "invalid-host", raw: "bad host:4739", wantErr: true},
		{name: "invalid-host-label", raw: "-bad.example.com:4739", wantErr: true},
		{name: "invalid-port", raw: "example.com:99999", wantErr: true},
		{name: "invalid-port-zero", raw: "example.com:0", wantErr: true},
		{name: "invalid-port-text", raw: "example.com:http", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addrs, err := parseCollectorAddresses(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(addrs) != tc.wantLen {
				t.Fatalf("expected %d addresses, got %d", tc.wantLen, len(addrs))
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	cfg := Config{
		LoadbalancerFlowLogsEnabled:                     true,
		LoadbalancerFlowLogsSender:                      "ipfix",
		LoadbalancerFlowLogsSenderIpfixCollectorAddress: "",
		LoadbalancerFlowLogsSenderProtocol:              "tcp",
	}
	if err := cfg.validate(); err == nil {
		t.Fatalf("expected error for empty collector address list")
	}

	cfg.LoadbalancerFlowLogsSenderIpfixCollectorAddress = "10.0.0.1:4739"
	if err := cfg.validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg.LoadbalancerFlowLogsSender = "ipfix"
	cfg.LoadbalancerFlowLogsSenderProtocol = "sctp"
	if err := cfg.validate(); err == nil {
		t.Fatalf("expected error for invalid sender protocol")
	}

	cfg.LoadbalancerFlowLogsSender = "stdout"
	cfg.LoadbalancerFlowLogsSenderProtocol = "sctp"
	cfg.LoadbalancerFlowLogsSenderIpfixCollectorAddress = "bad host:4739"
	if err := cfg.validate(); err != nil {
		t.Fatalf("unexpected error for stdout sender: %v", err)
	}

	cfg.LoadbalancerFlowLogsEnabled = false
	cfg.LoadbalancerFlowLogsSender = "ipfix"
	cfg.LoadbalancerFlowLogsSenderIpfixCollectorAddress = "bad host:4739"
	if err := cfg.validate(); err != nil {
		t.Fatalf("unexpected error for disabled flow logs: %v", err)
	}
}
