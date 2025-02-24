//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package types

import (
	"fmt"
	"net/netip"

	"github.com/spf13/pflag"
)

// Config registers a command-line flag on the agent to enable this subsystem
type Config struct {
	EnablePodIPMigration bool
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-pod-ip-migration", c.EnablePodIPMigration, "Enable support for pod IP migration (beta)")
	flags.MarkHidden("enable-pod-ip-migration")
}

const (
	// DetachedAnnotation is the name of the annotation for detached pods
	DetachedAnnotation = "cni.v1alpha1.isovalent.com/detached"
)

// DetachedIpamAddressPair is the value of detached annotations (encoded as JSON)
type DetachedIpamAddressPair struct {
	IPV4 *netip.Addr `json:"ipv4,omitempty"`
	IPV6 *netip.Addr `json:"ipv6,omitempty"`
}

func (p *DetachedIpamAddressPair) ipv4Valid() bool {
	return p.IPV4 != nil && p.IPV4.IsValid()
}

func (p *DetachedIpamAddressPair) ipv6Valid() bool {
	return p.IPV6 != nil && p.IPV6.IsValid()
}

func (p *DetachedIpamAddressPair) IsValid() bool {
	return p.ipv4Valid() || p.ipv6Valid()
}

func (p *DetachedIpamAddressPair) String() string {
	switch {
	case p.ipv4Valid() && p.ipv6Valid():
		return fmt.Sprintf("ipv4: %s/ipv6: %s", p.IPV4, p.IPV6)
	case p.ipv4Valid():
		return fmt.Sprintf("ipv4: %s", p.IPV4)
	case p.ipv6Valid():
		return fmt.Sprintf("ipv6: %s", p.IPV6)
	default:
		return "<invalid>"
	}
}

func (p *DetachedIpamAddressPair) DeepEqual(o *DetachedIpamAddressPair) bool {
	if o == nil {
		return false
	}

	if (p.IPV4 == nil) != (o.IPV4 == nil) {
		return false
	} else if p.IPV4 != nil {
		if *p.IPV4 != *o.IPV4 {
			return false
		}
	}

	if (p.IPV6 == nil) != (o.IPV6 == nil) {
		return false
	} else if p.IPV6 != nil {
		if *p.IPV6 != *o.IPV6 {
			return false
		}
	}

	return true
}
