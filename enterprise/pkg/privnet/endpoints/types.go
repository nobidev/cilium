//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package endpoints

import (
	"context"
	"fmt"
	"iter"
	"net/netip"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// PropertyPrivNetNetwork is the name of the network this endpoint is attached to. If unset, then the endpoint is
	// not attached to a custom private network.
	PropertyPrivNetNetwork = "isovalent-privnet-network"

	// PropertyPrivNetIPv4 contains the IPv4 address of the endpoint within the network.
	PropertyPrivNetIPv4 = "isovalent-privnet-ipv4-addr"

	// PropertyPrivNetIPv6 contains the IPv6 address of the endpoint within the network.
	PropertyPrivNetIPv6 = "isovalent-privnet-ipv6-addr"

	// PropertyPrivNetActivatedAt contains the timestamp when the endpoint became active.
	PropertyPrivNetActivatedAt = "isovalent-privnet-activated-at"
)

// EndpointGetter allows read operations on the endpoint manager.
// This is a custom interface to allow for slim mock implementations.
type EndpointGetter interface {
	Subscribe(s EndpointSubscriber)

	LookupCEPName(nsname string) (ep Endpoint)
	GetEndpointsByPodName(nsname string) iter.Seq[Endpoint]
}

// EndpointRemover allows the removal of endpoints on the endpoint manager.
// This is a custom interface to allow for slim mock implementations.
type EndpointRemover interface {
	RemoveByCEPName(nsname string) (Endpoint, error)
}

// EndpointCreator allows the creation of endpoints on the endpoint manager.
// This is a custom interface to allow for slim mock implementations.
type EndpointCreator interface {
	CreateEndpoint(ctx context.Context, epTemplate *models.EndpointChangeRequest) (Endpoint, error)
}

// Endpoint provides a subset of endpoint methods.
// This is a custom interface to allow for slim mock implementations.
type Endpoint interface {
	GetID16() uint16

	GetPropertyValue(key string) any
	SetPropertyValue(key string, value any) any
	IsProperty(key string) bool

	LXCMac() mac.MAC
	IPv4Address() netip.Addr
	GetIPv4Address() string
	IPv6Address() netip.Addr
	GetIPv6Address() string

	GetK8sNamespaceAndCEPName() string
	GetK8sNamespaceAndPodName() string

	SyncEndpointHeaderFile()
}

// EndpointSubscriber is endpointmanager.Subscriber but using the slim interfaces
// defined in this package.
type EndpointSubscriber interface {
	EndpointCreated(ep Endpoint)
	EndpointDeleted(ep Endpoint)
	EndpointRestored(ep Endpoint)
}

// EndpointPropertyProvider allows access to the endpoint properties.
// This is a custom interface to allow for slim mock implementations.
type EndpointPropertyProvider interface {
	GetPropertyValue(key string) any
}

// EndpointProperties is a type proxy for accessing the properties of an endpoint.
type EndpointProperties struct {
	network string
	ep      EndpointPropertyProvider
}

// ExtractEndpointProperties extracts the private network relevant endpoint properties.
// It returns (nil, false) if the given endpoint is not attached to a private network.
func ExtractEndpointProperties(ep EndpointPropertyProvider) (*EndpointProperties, bool) {
	network, ok := ep.GetPropertyValue(PropertyPrivNetNetwork).(string)
	if !ok || network == "" {
		return nil, false
	}

	return &EndpointProperties{
		network: network,
		ep:      ep,
	}, true
}

// PrivateNetwork returns the name of the private network this endpoint is attached to
func (p *EndpointProperties) PrivateNetwork() string {
	return p.network
}

// NetworkIPv4 returns the IPv4 address of the endpoint within the network.
func (p *EndpointProperties) NetworkIPv4() (netip.Addr, error) {
	addr, ok := p.ep.GetPropertyValue(PropertyPrivNetIPv4).(string)
	if !ok {
		return netip.Addr{}, nil
	}

	ipv4, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Addr{}, err
	} else if !ipv4.Is4() {
		return netip.Addr{}, fmt.Errorf("expected IPv4 address, got %s", addr)
	}

	return ipv4, nil
}

// NetworkIPv6 returns the IPv6 address of the endpoint within the network.
func (p *EndpointProperties) NetworkIPv6() (netip.Addr, error) {
	addr, ok := p.ep.GetPropertyValue(PropertyPrivNetIPv6).(string)
	if !ok {
		return netip.Addr{}, nil
	}

	ipv6, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Addr{}, err
	} else if !ipv6.Is6() {
		return netip.Addr{}, fmt.Errorf("expected IPv6 address, got %s", addr)
	}

	return ipv6, nil
}

// ActivatedAt returns the timestamp when the endpoint became active.
func (p *EndpointProperties) ActivatedAt() (time.Time, error) {
	datetime, ok := p.ep.GetPropertyValue(PropertyPrivNetActivatedAt).(string)
	if !ok {
		return time.Time{}, nil
	}

	return time.Parse(time.RFC3339Nano, datetime)
}

// FormatActivatedAtProperty is a helper to be used to format the PropertyPrivNetActivatedAt property.
func FormatActivatedAtProperty(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}
