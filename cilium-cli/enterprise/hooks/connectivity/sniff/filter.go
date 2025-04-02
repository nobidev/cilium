// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package sniff

import (
	"errors"
	"fmt"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/sniff"
	enterpriseFeatures "github.com/cilium/cilium/cilium-cli/enterprise/hooks/utils/features"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

// GetTunnelFilter returns a tcpdump filter which captures encapsulated packets.
//
// Differently than OSS sniff.GetTunnelFilter(), we should consider also the remote cluster
// configuration for mixed routing mode. For this reason, the resulting output filter can be:
// - `(localTunnelFilter or remoteTunnelFilter)`
// - `(localTunnelFilter)`
// - `(remoteTunnelFilter)`
// - an error otherwise.
func GetTunnelFilter(ct *check.ConnectivityTest) (string, error) {
	remoteCT := check.ConnectivityTest{Features: features.Set{}}
	remoteCT.Features[features.Tunnel] = ct.Features[enterpriseFeatures.RemoteClusterTunnel]
	remoteCT.Features[features.TunnelPort] = ct.Features[enterpriseFeatures.RemoteClusterTunnelPort]

	remoteTunnelFilter, remoteTunnelErr := sniff.GetTunnelFilter(&remoteCT)
	localTunnelFilter, localTunnelErr := sniff.GetTunnelFilter(ct)

	switch {
	case localTunnelErr == nil && remoteTunnelErr == nil && localTunnelFilter != remoteTunnelFilter:
		return fmt.Sprintf("(%s or %s)", localTunnelFilter, remoteTunnelFilter), nil
	case localTunnelErr == nil:
		return localTunnelFilter, nil
	case remoteTunnelErr == nil:
		return remoteTunnelFilter, nil
	}

	return "", errors.Join(localTunnelErr, remoteTunnelErr)
}
