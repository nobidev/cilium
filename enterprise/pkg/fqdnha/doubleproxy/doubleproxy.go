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
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/config"
	fqdnhaconfig "github.com/cilium/cilium/enterprise/pkg/fqdnha/config"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/tables"
	"github.com/cilium/cilium/pkg/endpointstate"
	fqdnproxy "github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/proxy/proxyports"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/time"
)

// The time we will wait for the remote proxy to ack any new rules
const RemoteProxyWaitTime = 10 * time.Second

// DoubleProxy is a shim for intercepting DNS proxy configuration; it wraps
// the existing DNS proxy while intercepting UpdateAllowed() calls
// and caching them in a StateDB table.
//
// When it is initialized, it "takes over" the existing DNS proxy singleton.
type DoubleProxy struct {
	log *slog.Logger
	ctx context.Context

	db              *statedb.DB
	configTable     statedb.RWTable[*tables.ProxyConfig]
	rpsTable        statedb.RWTable[tables.RemoteProxyState]
	restorerPromise promise.Promise[endpointstate.Restorer]
	shutdowner      hive.Shutdowner
	proxyPorts      *proxyports.ProxyPorts

	offlineEnabled bool

	// tracks consumers for synchronous proxy updates
	at *AckTrackers
}

type Params struct {
	cell.In

	Cfg        fqdnhaconfig.Config
	Log        *slog.Logger
	LC         cell.Lifecycle
	Shutdowner hive.Shutdowner

	DB                    *statedb.DB
	ConfigTable           statedb.RWTable[*tables.ProxyConfig]
	RemoteProxyStateTable statedb.RWTable[tables.RemoteProxyState]
	RestorerPromise       promise.Promise[endpointstate.Restorer]
	ProxyPorts            *proxyports.ProxyPorts
}

func NewDoubleProxy(p Params) *DoubleProxy {
	if !p.Cfg.EnableExternalDNSProxy {
		return nil
	}

	dp := &DoubleProxy{
		log:             p.Log,
		db:              p.DB,
		configTable:     p.ConfigTable,
		rpsTable:        p.RemoteProxyStateTable,
		restorerPromise: p.RestorerPromise,
		shutdowner:      p.Shutdowner,
		proxyPorts:      p.ProxyPorts,

		offlineEnabled: p.Cfg.EnableOfflineMode,

		at: NewAckTrackers(),
	}
	var cancel context.CancelFunc

	if p.LC != nil {
		dp.ctx, cancel = context.WithCancel(context.Background())
		p.LC.Append(cell.Hook{
			OnStop: func(hc cell.HookContext) error {
				cancel()
				return nil
			},
		})
	}

	return dp
}

func (dp *DoubleProxy) RegisterRemote() *AckTracker {
	return dp.at.Register()
}

func (dp *DoubleProxy) UnregisterRemote(at *AckTracker) {
	dp.at.Unregister(at)
}

type proxyWrapper struct {
	fqdnproxy.DNSProxier

	dp *DoubleProxy
}

// decorateDNSProxy wraps the existing local DNS proxy, adding a shim to intercept
// updateAllowed calls.
func DecorateDNSProxy(dp *DoubleProxy, dnsProxy fqdnproxy.DNSProxier) fqdnproxy.DNSProxier {
	if dp == nil || dnsProxy == nil {
		return dnsProxy
	}

	return &proxyWrapper{
		DNSProxier: dnsProxy,
		dp:         dp,
	}
}

// Listen opens the proxy, but also does a special dance when in fqdn-ha offline mode.
// Specifically, if offline mode is enabled *and* the remote proxy is running, then
// we must delay opening the socket until regeneration is complete.
//
// However, we must return immediately so that regeneration can proceed. This is OK,
// as there *is* a functioning DNS proxy listening on the desired port... it just
// isn't in-process.
// So, we return only when we're quite sure the remote proxy is up and running.
//
// In parallel, fqdnha/relay also blocks regeneration until the remote proxy has checked in,
// so we're certain that regeneration can't proceed without at least one working FQDN proxy.
func (pw *proxyWrapper) Listen(uint16) error {
	if !pw.dp.offlineEnabled {
		// FQDN proxy must be 10001
		return pw.DNSProxier.Listen(config.DNSProxyPort)
	}
	dp := pw.dp
	log := dp.log

	log.Info("--tofqdns-enable-offline-mode set; delaying opening FQDN proxy until regeneration completes")

	if dp.proxyPorts != nil { // nil for unit tests (otherwise we can't test this method)
		// Check local ports to see if there is a proxy running
		if _, ok := dp.proxyPorts.GetOpenLocalPorts()[config.DNSProxyPort]; !ok {
			log.Info("remote proxy is not running, opening DNS proxy immediately")
			return pw.DNSProxier.Listen(config.DNSProxyPort)
		}
	}

	// restartCtx is cancelled when we're ready to restart.
	// A bit of an abuse of contexts, but it's the easiest way to have
	// multiple parallel blockers that all get cleaned up.
	restartCtx, restartCancel := context.WithCancel(dp.ctx)

	// Paranoia: if the remote proxy goes down, then start the local one ASAP.
	go func() {
		_, err := tables.WaitForRemoteProxyStatus(restartCtx, dp.db, dp.rpsTable, pb.RemoteProxyStatus_RPS_UNSPECIFIED)
		if err == nil { // nil err means context wasn't canceled
			log.Warn("Remote FQDN-HA proxy went down! Starting DNS proxy.")
			restartCancel()
		}
	}()

	// Wait for regeneration to complete
	go func() {
		restorer, err := dp.restorerPromise.Await(restartCtx)
		if err != nil {
			restartCancel()
			return
		}
		restorer.WaitForEndpointRestore(restartCtx)
		log.Info("Endpoint regeneration complete. Starting DNS proxy.")
		restartCancel()
	}()

	// goroutine 3: wait until any blocker is done, then open local dns proxy.
	go func() {
		<-restartCtx.Done()
		err := pw.DNSProxier.Listen(config.DNSProxyPort)
		if err != nil {
			// Since this is in a goroutine, we must manually kill the agent.
			// The un-wrapped proxy would do so by returning `err`
			dp.shutdowner.Shutdown(hive.ShutdownWithError(fmt.Errorf("error opening dns proxy socket(s): %w", err)))
		}
	}()

	// return immediately: there is a functioning DNS proxy: the remote one.
	return nil
}

func (pw *proxyWrapper) GetBindPort() uint16 {
	return config.DNSProxyPort
}

func (pw *proxyWrapper) UpdateAllowed(endpointID uint64, destPortProto restore.PortProto, newRules policy.L7DataMap) (revert.RevertFunc, error) {
	revert, err := pw.DNSProxier.UpdateAllowed(endpointID, destPortProto, newRules)
	if err != nil {
		return revert, err
	}

	pw.dp.UpdateAllowed(endpointID, destPortProto, newRules)
	return revert, nil
}

func (dp *DoubleProxy) UpdateAllowed(endpointID uint64, destPortProto restore.PortProto, newRules policy.L7DataMap) {
	var err error

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
	ctx, cancel := context.WithTimeout(context.Background(), RemoteProxyWaitTime)
	defer cancel()
	if err := dp.at.WaitFor(ctx, dp.configTable.Revision(rtx)); err != nil {
		dp.log.Error("Timed out waiting for remote FQDN proxy to ack UpdateAllowed")
	}
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
