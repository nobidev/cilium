// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package relay

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/fqdn/namemanager"
	"github.com/cilium/cilium/pkg/policy/api"
)

type namemanagerWrapper struct {
	namemanager.NameManager
	p namemanagerWrapperParams
}

// Decorate the NameManager with additional, enterprise-only functionality: The
// FQDN HA proxy needs to now about FQDN selectors for offline policy updates,
// hence we interpose a NameManager wrapper here which forwards the registration
// (and deregistration) of FQDN Selectors to a statedb table.

type namemanagerWrapperParams struct {
	cell.In

	NameManager namemanager.NameManager
	// To track FQDN selectors.
	Table statedb.RWTable[FQDNSelector]
	DB    *statedb.DB
}

func NewNameManagerWrapper(params namemanagerWrapperParams) (*namemanagerWrapper, error) {
	w := &namemanagerWrapper{
		p: params,
	}
	return w, nil
}

// Used via DecorateAll, this replaces the normal NameManager with the namemanagerWrapper in the
// hive object graph.
func DecorateNameManager(nm namemanager.NameManager, mw *namemanagerWrapper) namemanager.NameManager {
	mw.NameManager = nm
	return mw
}

func (w *namemanagerWrapper) RegisterFQDNSelector(selector api.FQDNSelector) {
	w.NameManager.RegisterFQDNSelector(selector)

	wtx := w.p.DB.WriteTxn(w.p.Table)
	defer wtx.Abort()
	w.p.Table.Insert(wtx, FQDNSelector(selector))
	wtx.Commit()
}

func (w *namemanagerWrapper) UnregisterFQDNSelector(selector api.FQDNSelector) {
	w.NameManager.UnregisterFQDNSelector(selector)

	wtx := w.p.DB.WriteTxn(w.p.Table)
	defer wtx.Abort()
	w.p.Table.Delete(wtx, FQDNSelector(selector))
	wtx.Commit()
}
