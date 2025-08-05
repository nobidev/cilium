//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package extepspolicy

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/maps/policymap"
)

// Writer allows to interact with the policy map.
type Writer interface {
	// Upsert registers a policy map for the given IP address.
	Upsert(ip netip.Addr, pm *policymap.PolicyMap) error
	// Delete unregisters the policy map associated with the given IP address.
	Delete(ip netip.Addr) error
}
