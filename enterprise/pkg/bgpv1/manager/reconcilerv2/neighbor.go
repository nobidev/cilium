// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

// GetPeerAddressFromConfig returns peering address for the given peer from the provided BGPNodeInstance.
// If no error is returned and "exists" is false, it means that PeerAddress is not (yet) present in peer configuration.
func GetPeerAddressFromConfig(conf *v1alpha1.IsovalentBGPNodeInstance, peerName string) (addr netip.Addr, exists bool, err error) {
	if conf == nil {
		return netip.Addr{}, false, fmt.Errorf("passed instance is nil")
	}

	for _, peer := range conf.Peers {
		if peer.Name == peerName {
			if peer.PeerAddress != nil {
				addr, err = netip.ParseAddr(*peer.PeerAddress)
				return addr, true, err
			} else {
				return netip.Addr{}, false, nil // PeerAddress not present in peer configuration
			}
		}
	}
	return netip.Addr{}, false, fmt.Errorf("peer %s not found in instance %s", peerName, conf.Name)
}
