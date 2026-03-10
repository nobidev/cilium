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
	"net/netip"
	"testing"
)

func TestParseIPv4FromIPOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
		wantIP netip.Addr
		wantOK bool
	}{
		{
			name: "json output",
			output: `[{
				"ifname":"eth0",
				"addr_info":[{"family":"inet","local":"192.168.100.10","prefixlen":24}]
			}]`,
			wantIP: netip.MustParseAddr("192.168.100.10"),
			wantOK: true,
		},
		{
			name:   "invalid output",
			output: `eth0: no address`,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseIPv4FromIPOutput(tt.output)
			if ok != tt.wantOK {
				t.Fatalf("unexpected ok: got %v want %v", ok, tt.wantOK)
			}
			if got != tt.wantIP {
				t.Fatalf("unexpected ip: got %v want %v", got, tt.wantIP)
			}
		})
	}
}
