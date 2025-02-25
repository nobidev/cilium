//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressmapha

import (
	"unsafe"

	"github.com/cilium/cilium/pkg/types"
)

const (
	// PolicyStaticPrefixBits represents the size in bits of the static
	// prefix part of an egress policy key (i.e. the source IP).
	PolicyStaticPrefixBits = uint32(unsafe.Sizeof(types.IPv4{}) * 8)
	MaxPolicyEntries       = 1 << 14

	// This define must be kept in sync with EGRESS_GW_HA_MAX_GATEWAY_NODES in the datapath.
	maxGatewayNodes = 64
)
