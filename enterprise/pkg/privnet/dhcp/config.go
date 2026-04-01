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
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/time"
)

const (
	defaultRelayWaitTime = 500 * time.Millisecond

	FlagWaitTime = "private-networks-dhcp-wait-time"
)

var DefaultConfig = Config{
	WaitTime: defaultRelayWaitTime,
}

type Config struct {
	// WaitTime is the maximum time to collect DHCP responses.
	WaitTime time.Duration `mapstructure:"private-networks-dhcp-wait-time"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration(FlagWaitTime, def.WaitTime, "Maximum time to wait for DHCP relay responses")
	flags.MarkHidden(FlagWaitTime)
}
