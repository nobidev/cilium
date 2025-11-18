// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package gobgp

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/pkg/bgp/types"
)

// EnterpriseRouterProvider provides enterprise GoBGP server instances.
type EnterpriseRouterProvider struct{}

func NewEnterpriseRouterProvider() types.RouterProvider {
	return &EnterpriseRouterProvider{}
}

func (p *EnterpriseRouterProvider) NewRouter(ctx context.Context, log *slog.Logger, params types.ServerParameters) (types.Router, error) {
	return NewEnterpriseGoBGPServer(ctx, log, params)
}
