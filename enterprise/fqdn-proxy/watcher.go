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

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/u8proto"
)

type rulesWatcher struct {
	pb.UnimplementedFQDNProxyServer

	log        *slog.Logger
	grpcServer *grpc.Server

	proxy  *dnsproxy.DNSProxy
	client *fqdnAgentClient

	// Closed when first set of rules is received, indicating it's safe
	// to open the socket.
	rulesReceived chan struct{}
	onFirstRule   func()

	muteErrors bool // if true, don't log subsequent reconnects
}

func newRulesWatcher(log *slog.Logger, proxy *dnsproxy.DNSProxy, client *fqdnAgentClient) *rulesWatcher {
	rw := &rulesWatcher{
		log:           log,
		proxy:         proxy,
		client:        client,
		rulesReceived: make(chan struct{}),
	}
	rw.onFirstRule = sync.OnceFunc(func() { close(rw.rulesReceived) })
	return rw

}

// watchRules plumbs the rule pipeline from the agent to the proxy.
// Rules are the set of allowed FQDNs a given endpoint is allowed to query.
func (rw *rulesWatcher) watchRules() <-chan struct{} {
	go rw.doWatchRules()
	return rw.rulesReceived
}

func (rw *rulesWatcher) doWatchRules() {
	for {
		// First things first: try the SubscribeRules method.
		err := rw.trySubscribeRules()

		// does the agent not support subscription? Fall back to local gRPC server,
		// but retry if the agent restarts.
		if isUnimplementedError(err) {
			rw.log.Info("Agent does not support SubscribeFQDNRules(), falling back to gRPC server.")
			rw.runServer(rw.proxy) // launches another goroutine
			// every 5 minutes, retry

			sctx, cancel := context.WithTimeout(context.TODO(), 5*time.Minute)
			rw.client.WaitMaybeReconnected(sctx) // Wait for agent to restart, then try again
			cancel()
		} else if err != nil {
			if rw.client.shouldLog(err) {
				rw.log.Info("SubscribeFQDNRules() request failed", logfields.Error, err)
			}

			// Sleep until connected or 0.5 seconds
			sctx, cancel := context.WithTimeout(context.TODO(), 500*time.Millisecond)
			rw.client.WaitMaybeConnected(sctx)
			cancel()
		}
	}
}

// trySubscribeRules connects to the remote agent's gRPC api, issuing
// a SubscribeFQDNRules() call when connected.
//
// It then watches the stream, applying changes to the proxy. Blocks
// until disconnected -- error is never nil.
func (rw *rulesWatcher) trySubscribeRules() error {
	rulesStream, err := rw.client.SubscribeFQDNRules(context.Background())
	if err != nil {
		return fmt.Errorf("SubscribeFQDNRules failed: %w", err)
	}

	rw.muteErrors = false
	rw.log.Info("Established SubscribeFQDNRules stream")

	for {
		rule, err := rulesStream.Recv()
		if err != nil {
			return fmt.Errorf("SubscribeFQDNRules stream recv error: %w", err)
		}

		// It is safe to shut down the gRPC server now; we have a successful rule subscription
		// noop if already stopped
		rw.stopServer()

		err = rw.updateAllowed(rule)
		if err != nil {
			rw.log.Error("Failed to apply invalid rule to proxy",
				logfields.Error, err,
				logfields.EndpointID, rule.EndpointID,
			)
		}
		err = rulesStream.Send(&pb.Empty{}) // ack the rule
		if err != nil {
			return fmt.Errorf("SubscribeFQDNRules stream send error: %w", err)
		}
	}
}

// runServer starts the local gRPC server, which accepts UpdateAllowed requests
// from the agent to the proxy.
//
// When running with newer agents, we do not start this server.
func (rw *rulesWatcher) runServer(proxy *dnsproxy.DNSProxy) {
	socket := "/var/run/cilium/proxy.sock"
	os.Remove(socket)
	lis, err := net.Listen("unix", socket)
	if err != nil {
		rw.log.Error("failed to listen", logfields.Error, err)
		os.Exit(1)
	}
	var opts []grpc.ServerOption
	rw.grpcServer = grpc.NewServer(opts...)
	pb.RegisterFQDNProxyServer(rw.grpcServer, rw)
	go rw.grpcServer.Serve(lis)
}

func (rw *rulesWatcher) stopServer() {
	if rw.grpcServer == nil {
		return
	}

	rw.grpcServer.GracefulStop()
	rw.grpcServer = nil
}

func (rw *rulesWatcher) UpdateAllowed(ctx context.Context, rules *pb.FQDNRules) (*pb.Empty, error) {
	err := rw.updateAllowed(rules)
	if err != nil {
		rw.log.Error("Failed to apply invalid rule to proxy",
			logfields.Error, err,
			logfields.Endpoint, rules.EndpointID)
	}
	return &pb.Empty{}, err
}

func (rw *rulesWatcher) RemoveRestoredRules(ctx context.Context, endpointIDMsg *pb.EndpointID) (*pb.Empty, error) {
	// noop, but implemented so that agents don't see an error.
	return &pb.Empty{}, nil
}

func (rw *rulesWatcher) GetRules(ctx context.Context, endpointIDMsg *pb.EndpointID) (*pb.RestoredRules, error) {
	// noop, never actually called by the agent, return empty result
	return &pb.RestoredRules{}, nil
}

func (rw *rulesWatcher) updateAllowed(rules *pb.FQDNRules) error {
	// If this is the first rule, tell the proxy to open the socket.
	rw.onFirstRule()

	var portProto restore.PortProto
	if rules.DestProto == 0 {
		portProto = restore.PortProto(rules.DestPort)
	} else {
		portProto = restore.MakeV2PortProto(uint16(rules.DestPort), u8proto.U8proto(rules.DestProto))
	}

	rw.log.Info("Updating rules for endpoint",
		logfields.Endpoint, rules.EndpointID,
		logfields.Port, portProto.Port(),
		logfields.Protocol, portProto.Protocol(),
		logfields.Count, len(rules.Rules.SelectorRegexMapping),
	)

	cachedSelectorREEntry := make(dnsproxy.CachedSelectorREEntry)

	for key, rule := range rules.Rules.SelectorRegexMapping {
		regex, err := regexp.Compile(rule)
		if err != nil {
			return err
		}

		ids, ok := rules.Rules.SelectorIdentitiesMapping[key]
		if !ok {
			return fmt.Errorf("malformed message: key %s not found in identities mapping", key)
		}

		nids := make([]identity.NumericIdentity, len(ids.List))

		for i, id := range ids.List {
			nids[i] = identity.NumericIdentity(id)
		}

		selector := SimpleSelector{
			identities: nids,
			name:       key,
		}

		cachedSelectorREEntry[&selector] = regex
	}

	return rw.proxy.UpdateAllowedFromSelectorRegexes(rules.EndpointID, portProto, cachedSelectorREEntry)
}

// isUnimplementedError returns true if err is a
// gRPC Status error, and the status code indicates an
// unimplemented method.
func isUnimplementedError(err error) bool {
	if err == nil {
		return false
	}
	sts, ok := status.FromError(err)
	// This agent does not support SubscribeFQDN
	if ok && sts.Code() == codes.Unimplemented {
		return true
	}
	return false
}
