//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package dhcp

import (
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/time"
)

// TestConfig allows tests to override runtime settings.
// It should only be wired in test hives.
type TestConfig struct {
	// NetNS overrides the network namespace used by DHCP relays/server in tests.
	NetNS *netns.NetNS

	// LeaseSweepInterval overrides the DHCP lease sweeper interval in tests.
	LeaseSweepInterval time.Duration
}
