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

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	fqdnhaconfig "github.com/cilium/cilium/enterprise/pkg/fqdnha/config"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/tables"
	fqdnproxy "github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
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

	db          *statedb.DB
	configTable statedb.RWTable[*tables.ProxyConfig]

	// tracks consumers for synchronous proxy updates
	at *AckTrackers
}

type Params struct {
	cell.In

	Cfg fqdnhaconfig.Config
	Log *slog.Logger

	DB          *statedb.DB
	ConfigTable statedb.RWTable[*tables.ProxyConfig]
}

func NewDoubleProxy(p Params) *DoubleProxy {
	if !p.Cfg.EnableExternalDNSProxy {
		return nil
	}

	dp := &DoubleProxy{
		log:         p.Log,
		db:          p.DB,
		configTable: p.ConfigTable,

		at: NewAckTrackers(),
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
	if dp == nil {
		return dnsProxy
	}

	return &proxyWrapper{
		DNSProxier: dnsProxy,
		dp:         dp,
	}
}

func (pw *proxyWrapper) Listen(uint16) error {
	// FQDN proxy must be 10001
	return pw.DNSProxier.Listen(10001)
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
