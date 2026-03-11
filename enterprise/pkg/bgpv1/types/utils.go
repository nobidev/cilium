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
	"strconv"
	"strings"
)

// ParseCommunity parses community string in the "<0-65535>:<0-65535>" format or single decimal
// number string format and returns it as a decimal value that can used in GoBGP API calls.
// Note that GoBGP does not expose this parser as a public API (yet), that's why we have our own implementation.
func ParseCommunity(communityStr string) (uint32, error) {
	// parse as <0-65535>:<0-65535>
	if elems := strings.Split(communityStr, ":"); len(elems) == 2 {
		fst, err := strconv.ParseUint(elems[0], 10, 16)
		if err != nil {
			return 0, err
		}
		snd, err := strconv.ParseUint(elems[1], 10, 16)
		if err != nil {
			return 0, err
		}
		return uint32(fst<<16 | snd), nil
	}
	// parse as a single decimal number
	c, err := strconv.ParseUint(communityStr, 10, 32)
	return uint32(c), err
}

// NewCommunity returns a decimal value representing BGP community that can used in GoBGP API calls
// from two 16-bit numbers (ASN and value).
func NewCommunity(asn uint16, val uint16) uint32 {
	return uint32(asn)<<16 | uint32(val)
}
