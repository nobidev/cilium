//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package relay

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/fqdn/namemanager"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
)

type namemanagerWrapper struct {
	namemanager.NameManager
	p namemanagerWrapperParams
}

// Decorate the NameManager with additional, enterprise-only functionality: The
// FQDN HA proxy needs to know about FQDN selectors for offline policy updates,
// hence we interpose a NameManager wrapper here which forwards the registration
// (and deregistration) of FQDN Selectors to a statedb table.

type namemanagerWrapperParams struct {
	cell.In

	NameManager namemanager.NameManager
	// To track FQDN selectors.
	Table statedb.RWTable[FQDNSelector]
	DB    *statedb.DB
}

func NewNameManagerWrapper(params namemanagerWrapperParams) *namemanagerWrapper {
	return &namemanagerWrapper{
		p: params,
	}
}

// Used via DecorateAll, this replaces the normal NameManager with the namemanagerWrapper in the
// hive object graph.
func DecorateNameManager(pr policy.PolicyRepository, nm namemanager.NameManager, mw *namemanagerWrapper) namemanager.NameManager {
	mw.NameManager = nm

	// The NameManager does this to break a Hive import loop; we must do the same :-/
	pr.GetSelectorCache().SetLocalIdentityNotifier(mw)
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
