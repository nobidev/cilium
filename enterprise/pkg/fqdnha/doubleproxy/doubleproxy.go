//nolint:goheader
//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package doubleproxy

import (
	"context"
	"log/slog"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/daemon/cmd"
	fqdnhaconfig "github.com/cilium/cilium/enterprise/pkg/fqdnha/config"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/remoteproxy"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/tables"
	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/defaultdns"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	fqdnproxy "github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/time"
)

var _ fqdnproxy.DNSProxier = &DoubleProxy{}

// The time we will wait for the remote proxy to ack any new rules
const RemoteProxyWaitTime = 10 * time.Second

// DoubleProxy is a shim for relaying proxy function calls to a local and remote proxies.
// LocalProxy is always set, RemoteProxy may be nil
type DoubleProxy struct {
	ctx    context.Context
	cancel context.CancelFunc

	RemoteProxy *remoteproxy.RemoteFQDNProxy
	LocalProxy  *dnsproxy.DNSProxy

	defaultProxy  defaultdns.Proxy
	daemonPromise promise.Promise[*cmd.Daemon]
	log           *slog.Logger

	db          *statedb.DB
	configTable statedb.RWTable[*tables.ProxyConfig]
	// done when the table is first initialized
	initialized sync.WaitGroup

	// tracks consumers for synchronous proxy updates
	at *AckTrackers
}

type Params struct {
	cell.In

	Lc            cell.Lifecycle
	DaemonPromise promise.Promise[*cmd.Daemon]
	DefaultProxy  defaultdns.Proxy
	RemoteProxy   *remoteproxy.RemoteFQDNProxy
	Cfg           fqdnhaconfig.Config
	Log           *slog.Logger

	DB *statedb.DB
}

func NewDoubleProxy(
	p Params,
) (*DoubleProxy, statedb.Table[*tables.ProxyConfig], error) {
	if !p.Cfg.EnableExternalDNSProxy {
		return nil, nil, nil
	}
	dp := &DoubleProxy{
		RemoteProxy:   p.RemoteProxy,
		defaultProxy:  p.DefaultProxy,
		daemonPromise: p.DaemonPromise,
		log:           p.Log,

		db:          p.DB,
		initialized: sync.WaitGroup{},

		at: NewAckTrackers(),
	}

	dp.ctx, dp.cancel = context.WithCancel(context.Background())

	var err error
	dp.configTable, err = tables.NewProxyConfigTable(p.Cfg, p.DB)
	if err != nil {
		return nil, nil, err
	}

	dp.initialized.Add(1)
	p.Lc.Append(dp)
	return dp, dp.configTable.ToTable(), nil
}

func (dp *DoubleProxy) Start(ctx cell.HookContext) error {
	// Wait for the daemon to be populated, at which point we can assume defaultProxy to be set.
	_, err := dp.daemonPromise.Await(ctx)
	if err != nil {
		return err
	}

	dp.LocalProxy = dp.defaultProxy.Get().(*dnsproxy.DNSProxy)
	dp.defaultProxy.Set(dp)
	dp.RemoteProxy.ProvideLocalProxy(dp.LocalProxy)

	dp.loadTable()
	return nil
}

// loadTable Populates the ProxyConfig table with the existing state
// from the local proxy.
func (dp *DoubleProxy) loadTable() {
	rules := dp.LocalProxy.DumpRules()
	wtx := dp.db.WriteTxn(dp.configTable)
	defer wtx.Abort()
	for _, rule := range rules {
		_, _, err := dp.configTable.Insert(wtx, tables.NewProxyConfigFromMsg(rule))
		if err != nil {
			dp.log.Error("failed to insert endpoint fqdn rules on initial list", logfields.Error, err)
		}
	}
	wtx.Commit()
	dp.log.Info("loaded rules from existing proxy", logfields.Count, len(rules))
	dp.initialized.Done()
}

func (dp *DoubleProxy) Stop(ctx cell.HookContext) error {
	dp.cancel()
	return nil
}

func (dp *DoubleProxy) RegisterRemote() *AckTracker {
	return dp.at.Register()
}

func (dp *DoubleProxy) UnregisterRemote(at *AckTracker) {
	dp.at.Unregister(at)
}

func (dp *DoubleProxy) GetRules(v *versioned.VersionHandle, u uint16) (restore.DNSRules, error) {
	return dp.LocalProxy.GetRules(v, u)
}

func (dp *DoubleProxy) RemoveRestoredRules(u uint16) {
	// remote proxy no longer uses restored rules; safe to
	// send only to local proxy.

	dp.LocalProxy.RemoveRestoredRules(u)
}

func (dp *DoubleProxy) UpdateAllowed(endpointID uint64, destPortProto restore.PortProto, newRules policy.L7DataMap) (revert.RevertFunc, error) {
	revert, err := dp.LocalProxy.UpdateAllowed(endpointID, destPortProto, newRules)
	if err != nil {
		return nil, err
	}
	if dp.RemoteProxy != nil {
		err = dp.RemoteProxy.UpdateAllowed(endpointID, destPortProto, newRules)
		if err != nil {
			return nil, err
		}
	}

	// need to wait for the table to be first initialized so we don't accidentally overwrite
	// old entries from Dump during an UpdateAllowed call.
	dp.initialized.Wait()

	wtx := dp.db.WriteTxn(dp.configTable)
	defer wtx.Abort()
	if len(newRules) == 0 {
		err = dp.deleteRule(wtx, endpointID, destPortProto)
	} else {
		_, _, err = dp.configTable.Insert(wtx, tables.NewProxyConfig(endpointID, destPortProto, newRules))
	}
	if err != nil {
		dp.log.Error("failed to insert / delete endpoint fqdn rules", logfields.Error, err)
	}
	rtx := wtx.Commit()

	// Wait for any downstream consumers to ack
	ctx, cancel := context.WithTimeout(dp.ctx, RemoteProxyWaitTime)
	defer cancel()
	if err := dp.at.WaitFor(ctx, dp.configTable.Revision(rtx)); err != nil {
		dp.log.Error("Timed out waiting for remote FQDN proxy to ack UpdateAllowed")
	}

	return revert, nil
}

func (dp *DoubleProxy) deleteRule(wtx statedb.WriteTxn, endpointID uint64, destPortProto restore.PortProto) error {
	obj, _, found := dp.configTable.Get(wtx, tables.ConfigByKey(tables.ProxyConfigKey{
		EndpointID: uint16(endpointID),
		PortProto:  destPortProto,
	}))
	if !found {
		return nil
	}
	_, _, err := dp.configTable.Delete(wtx, obj)
	return err
}

func (dp *DoubleProxy) GetBindPort() uint16 {
	return dp.LocalProxy.GetBindPort()
}

// SetRejectReply is only called during bootstrap, before
// we're injected
func (dp *DoubleProxy) SetRejectReply(s string) {
	dp.log.Error("BUG: DoubleProxy.SetRejectReply() called -- it never should be")
	dp.LocalProxy.SetRejectReply(s)
}

// RestoreRules is called early in the startup process,
// before we're able to inject the DoubleProxy.
// So, this should never actually be hit.
func (dp *DoubleProxy) RestoreRules(op *endpoint.Endpoint) {
	dp.log.Error("BUG: DoubleProxy.RestoreRules() called -- it never should be")
	dp.LocalProxy.RestoreRules(op)
}

func (dp *DoubleProxy) Cleanup() {
	dp.LocalProxy.Cleanup()
	dp.RemoteProxy.Cleanup()
}
