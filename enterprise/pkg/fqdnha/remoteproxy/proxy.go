//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package remoteproxy

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	fqdnhaconfig "github.com/cilium/cilium/enterprise/pkg/fqdnha/config"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/doubleproxy"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/time"

	fqdnpb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
)

const (
	fqdnUpdateTimeout = 10 * time.Second
)

// RemoteFQDNProxy is a gRPC client used to communicate with the external
// fqdn-proxy.
//
// It handles FQDN rules updates and send them to the remote fqdn-proxy
// via a gRPC connection. The updates are identified by their fqdnRuleKey key,
// which is also used to deduplicate them. This is done to reduce the gRPC
// calls from the proxy plugin to the external fqdn-proxy and to guarantee
// that the latest update version will be sent to the fqdn-proxy.
//
// the general flow is that update events are intercepted by the DoubleProxy, pushed
// to the local proxy, then pushed to the remote proxy. However, we first
// connect to the remote proxy, we need to replay all existing rules first.
//
// This is accomplished by looking at the current state of the local proxy
// and synthezising an update for all already-existing endpoints.
type RemoteFQDNProxy struct {
	log *slog.Logger

	dp          doubleProxy
	db          *statedb.DB
	configTable statedb.Table[*tables.ProxyConfig]
}

type doubleProxy interface {
	RegisterRemote() *doubleproxy.AckTracker
	UnregisterRemote(at *doubleproxy.AckTracker)
}

type Params struct {
	cell.In

	JobGroup job.Group

	L7Proxy *proxy.Proxy
	DP      *doubleproxy.DoubleProxy
	Cfg     fqdnhaconfig.Config
	Log     *slog.Logger

	DB          *statedb.DB
	ConfigTable statedb.Table[*tables.ProxyConfig]
}

func NewRemoteFQDNProxy(p Params) (*RemoteFQDNProxy, error) {
	if !p.Cfg.EnableExternalDNSProxy {
		return nil, nil
	}

	rp := &RemoteFQDNProxy{
		db:          p.DB,
		configTable: p.ConfigTable,
		dp:          p.DP,

		log: p.Log.WithGroup("remote-fqdn-proxy"),
	}
	p.JobGroup.Add(job.OneShot("forward-fqdn-updates", rp.run))
	return rp, nil
}

func (r *RemoteFQDNProxy) run(ctx context.Context, health cell.Health) error {
	for {
		r.log.Debug("trying to connect to remote proxy...")
		// create a new connection from the agent to the remote fqdn proxy
		var err error
		connection, err := grpc.DialContext(
			ctx,
			"unix:///var/run/cilium/proxy.sock",
			grpc.WithInsecure(),
			grpc.WithBlock(),
			grpc.WithIdleTimeout(time.Duration(0)),
		)
		if err != nil {
			r.log.Error("Failed to dial remote proxy server",
				logfields.Error, err)
		} else {
			health.OK("Connected to remote proxy")
			cctx, cancel := context.WithCancel(ctx)
			go func() {
				// If the connection fails, immediately cancel the child context.
				connection.WaitForStateChange(ctx, connectivity.Ready)
				r.log.Info("FQDN remote proxy connection state changed",
					logfields.State, connection.GetState())
				cancel()
			}()
			err = r.forwardUpdates(cctx, fqdnpb.NewFQDNProxyClient(connection))
			cancel() // just in case we cancelled due to forwarding issues.
		}
		if err != nil {
			health.Degraded("Not connected to remote proxy", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1 * time.Second):
			continue
		}
	}
}

// forwardUpdates is called when the gRPC client successfully connects to the remote proxy.
//
// It dumps the current state of the system in order to bootstrap, queues this for forwarding, then
// starts handling update events until ctx is cancelled.
func (r *RemoteFQDNProxy) forwardUpdates(ctx context.Context, client fqdnpb.FQDNProxyClient) error {
	r.log.Info("Successfully connected to remote FQDN proxy, initializing...")

	at := r.dp.RegisterRemote()
	defer r.dp.UnregisterRemote(at)

	wtxn := r.db.WriteTxn(r.configTable)
	changeIter, err := r.configTable.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		r.log.Error("BUG: failed to watch config table", logfields.Error, err)
		return err
	}

	for {
		changes, watch := changeIter.Next(r.db.ReadTxn())
		for change, rev := range changes {
			msg := change.Object.ToMsg(change.Deleted)

			cctx, cancel := context.WithTimeout(ctx, fqdnUpdateTimeout)
			defer cancel()

			if _, err := client.UpdateAllowed(cctx, msg); err != nil {
				r.log.Error("Failed to forward FQDN rules update to remote proxy",
					logfields.NewRules, msg.Rules,
					logfields.EndpointID, msg.EndpointID,
					logfields.Error, err)
				return fmt.Errorf("failed to forward FQDN rules to remote proxy: %w", err)
			}
			at.Ack(rev) // notify DoubleProxy that we reached this revision
			r.log.Debug("Forwarded UpdateAllowed() to remote FQDN proxy",
				logfields.NewRules, msg.Rules,
				logfields.EndpointID, msg.EndpointID)

			eid := &fqdnpb.EndpointID{EndpointID: uint32(msg.EndpointID)}
			// RemoveRestoredRules for this endpoint as well.
			// Only consumed by old (pre-1.17) proxies
			if _, err := client.RemoveRestoredRules(cctx, eid); err != nil {
				r.log.Error("Failed to forward RemoveRestoredRules to remote proxy",
					logfields.Error, err)
				return fmt.Errorf("failed to RemoveRestoredRules in remote proxy: %w", err)
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-watch:
		}
	}
}
