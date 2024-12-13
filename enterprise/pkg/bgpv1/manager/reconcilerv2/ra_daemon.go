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
	"context"
	"fmt"

	"github.com/YutaroHayakawa/go-ra"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
)

type RADaemon interface {
	Run(ctx context.Context)
	Reload(ctx context.Context, newConfig *ra.Config) error
	Status() *ra.Status
}

func newRADaemon(bgpConfig config.Config) (RADaemon, error) {
	if !bgpConfig.Enabled {
		return nil, nil
	}
	raDaemon, err := ra.NewDaemon(&ra.Config{
		Interfaces: nil,
	})
	if err != nil {
		return nil, fmt.Errorf("failed creating new RA Daemon: %w", err)
	}
	return raDaemon, nil
}
