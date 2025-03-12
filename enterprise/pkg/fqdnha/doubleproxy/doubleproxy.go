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
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/daemon/cmd"
	fqdnhaconfig "github.com/cilium/cilium/enterprise/pkg/fqdnha/config"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/remoteproxy"
	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/defaultdns"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	fqdnproxy "github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/revert"
)

var _ fqdnproxy.DNSProxier = &DoubleProxy{}

// DoubleProxy is a shim for relaying proxy function calls to a local and remote proxies.
// LocalProxy is always set, RemoteProxy may be nil
type DoubleProxy struct {
	RemoteProxy *remoteproxy.RemoteFQDNProxy
	LocalProxy  *dnsproxy.DNSProxy

	defaultProxy  defaultdns.Proxy
	daemonPromise promise.Promise[*cmd.Daemon]
	log           *slog.Logger
}

type params struct {
	cell.In

	DaemonPromise promise.Promise[*cmd.Daemon]
	DefaultProxy  defaultdns.Proxy
	RemoteProxy   *remoteproxy.RemoteFQDNProxy
	Cfg           fqdnhaconfig.Config
	Log           *slog.Logger
}

func NewDoubleProxy(
	lc cell.Lifecycle,
	p params,
) *DoubleProxy {
	if !p.Cfg.EnableExternalDNSProxy {
		return nil
	}
	dp := &DoubleProxy{
		RemoteProxy:   p.RemoteProxy,
		defaultProxy:  p.DefaultProxy,
		daemonPromise: p.DaemonPromise,
		log:           p.Log,
	}
	lc.Append(dp)
	return dp
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

	return nil
}

func (dp *DoubleProxy) Stop(ctx cell.HookContext) error {
	return nil
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
	return revert, nil
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
