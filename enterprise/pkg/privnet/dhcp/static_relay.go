// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dhcp

import (
	"context"
	"fmt"
	"net"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/time"
)

// StaticRelay returns DHCP replies with a static IPv4 lease.
type StaticRelay struct {
	// ServerIP is the DHCP server identifier (optional).
	ServerIP net.IP

	// LeaseIP is the IPv4 address offered/acked to the client.
	LeaseIP net.IP

	// Lease is the DHCP lease duration (optional).
	Lease time.Duration

	// Renew is the renewal time (T1) (optional).
	Renew time.Duration

	// SubnetMask is the IPv4 subnet mask (optional).
	SubnetMask net.IP

	// Router is the default gateway (optional).
	Router net.IP
}

// StaticRelayFactory returns the same StaticRelay for each workload.
type StaticRelayFactory struct {
	Relay *StaticRelay
}

// RelayFor implements RelayFactory.
func (f *StaticRelayFactory) RelayFor(*tables.LocalWorkload) (Relayer, error) {
	if f == nil || f.Relay == nil {
		return nil, nil
	}
	return f.Relay, nil
}

// Relay implements Relay.
func (r *StaticRelay) Relay(_ context.Context, _ time.Duration, req *dhcpv4.DHCPv4) ([]*dhcpv4.DHCPv4, error) {
	if req == nil {
		return nil, nil
	}

	respType, ok := responseType(req.MessageType())
	if !ok {
		return nil, nil
	}

	leaseIP := r.LeaseIP.To4()
	if leaseIP == nil {
		return nil, fmt.Errorf("invalid lease IPv4 address %q", r.LeaseIP)
	}

	resp, err := dhcpv4.NewReplyFromRequest(req)
	if err != nil {
		return nil, err
	}
	resp.YourIPAddr = leaseIP
	resp.UpdateOption(dhcpv4.OptMessageType(respType))

	if serverIP := r.ServerIP.To4(); serverIP != nil {
		resp.UpdateOption(dhcpv4.OptServerIdentifier(serverIP))
	} else if r.ServerIP != nil {
		return nil, fmt.Errorf("invalid server IPv4 address %q", r.ServerIP)
	}

	if mask := r.SubnetMask.To4(); mask != nil {
		resp.UpdateOption(dhcpv4.OptSubnetMask(net.IPv4Mask(mask[0], mask[1], mask[2], mask[3])))
	} else if r.SubnetMask != nil {
		return nil, fmt.Errorf("invalid subnet mask %q", r.SubnetMask)
	}

	if router := r.Router.To4(); router != nil {
		resp.UpdateOption(dhcpv4.OptRouter(router))
	} else if r.Router != nil {
		return nil, fmt.Errorf("invalid router IPv4 address %q", r.Router)
	}

	if r.Lease > 0 {
		resp.UpdateOption(dhcpv4.OptIPAddressLeaseTime(r.Lease))
	}
	if r.Renew > 0 {
		resp.UpdateOption(dhcpv4.OptRenewTimeValue(r.Renew))
	}

	return []*dhcpv4.DHCPv4{resp}, nil
}

func responseType(t dhcpv4.MessageType) (dhcpv4.MessageType, bool) {
	switch t {
	case dhcpv4.MessageTypeDiscover:
		return dhcpv4.MessageTypeOffer, true
	case dhcpv4.MessageTypeRequest:
		return dhcpv4.MessageTypeAck, true
	default:
		return 0, false
	}
}
