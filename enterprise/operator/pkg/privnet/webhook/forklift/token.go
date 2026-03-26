// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package forklift

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/lock"
)

// TokenVault provides access to a bearer token.
type TokenVault interface{ Token() string }

type tokenVault struct {
	path string

	mu    lock.RWMutex
	token string
}

func newTokenVault(path string, lc cell.Lifecycle, jg job.Group) TokenVault {
	const reloadInterval = 5 * time.Minute

	var tr = &tokenVault{path: path}
	lc.Append(
		cell.Hook{
			// Load the token once synchronously, to ensure that all consumers
			// can immediately leverage it.
			OnStart: func(hc cell.HookContext) error {
				if err := tr.reload(hc); err != nil {
					return err
				}

				jg.Add(
					job.Timer("reload-token", tr.reload, reloadInterval),
				)

				return nil
			},
		},
	)

	return tr
}

func (tr *tokenVault) Token() string {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	return tr.token
}

func (tr *tokenVault) reload(context.Context) error {
	token, err := os.ReadFile(tr.path)
	if err != nil {
		return fmt.Errorf("reading bearer token: %w", err)
	}

	tr.mu.Lock()
	tr.token = string(token)
	tr.mu.Unlock()

	return nil
}
