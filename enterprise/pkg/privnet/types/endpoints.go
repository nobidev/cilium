// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package types

import (
	"bytes"
	"maps"
	"net/netip"

	"github.com/cilium/cilium/pkg/mac"
)

type EndpointProperties struct {
	Network    string
	MAC        mac.MAC
	IPv4, IPv6 netip.Addr
	Labels     map[string]string
}

func (e *EndpointProperties) Equal(other *EndpointProperties) bool {
	return e.Network == other.Network &&
		e.IPv4 == other.IPv4 &&
		e.IPv6 == other.IPv6 &&
		bytes.Equal(e.MAC, other.MAC) &&
		maps.Equal(e.Labels, other.Labels)
}
