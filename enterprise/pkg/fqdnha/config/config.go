//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package config

import "github.com/spf13/pflag"

// Agent and proxy must use the same hardcoded port for the DNS server
const DNSProxyPort = 10001

// Config is the enterprise FQDN proxy configuration.
type Config struct {
	EnableExternalDNSProxy bool `mapstructure:"external-dns-proxy"`
	EnableOfflineMode      bool `mapstructure:"tofqdns-enable-offline-mode"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("external-dns-proxy", def.EnableExternalDNSProxy, "Enable Cilium agent to use an external DNS proxy")
	flags.Bool("tofqdns-enable-offline-mode", def.EnableOfflineMode, "DNS Proxy will use the Cilium agent's bpf maps directly rather than getting information from the agent's dns proxy service.")
	flags.MarkHidden("tofqdns-enable-offline-mode")
}
