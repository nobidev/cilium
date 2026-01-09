//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"slices"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"
)

// rulesWatcher provides the proxy with per-endpoint L7 DNS rules.
// It does so by either using the SubscribeFQDNRules gRPC stream from v1.18+ agents,
// or starting a gRPC server for pre-v1.18 agents to push rules to.
type rulesWatcher struct {
	pb.UnimplementedFQDNProxyServer

	log        *slog.Logger
	grpcServer *grpc.Server

	proxySet chan struct{}
	proxy    *dnsproxy.DNSProxy
	client   *fqdnAgentClient

	// Closed when first set of rules is received, indicating it's safe
	// to open the socket.
	rulesReceived chan struct{}
	onFirstRule   func()
}

func newRulesWatcher(log *slog.Logger, client *fqdnAgentClient, jg job.Group) *rulesWatcher {
	rw := &rulesWatcher{
		log:           log.With(logfields.LogSubsys, "rules-watcher"),
		client:        client,
		rulesReceived: make(chan struct{}),
		proxySet:      make(chan struct{}),
	}
	rw.onFirstRule = sync.OnceFunc(func() { close(rw.rulesReceived) })

	jg.Add(job.OneShot("rules-watcher", rw.doWatchRules, job.WithShutdown()))

	return rw
}

// waitForRules plumbs the rule pipeline from the agent to the proxy.
// Rules are the set of allowed FQDNs a given endpoint is allowed to query.
//
// proxy is a parameter to break a hive circular dependency.
//
// returns a channel that is closed when the first endpoint is received.
func (rw *rulesWatcher) waitForRules(proxy *dnsproxy.DNSProxy) <-chan struct{} {
	rw.proxy = proxy
	close(rw.proxySet)
	return rw.rulesReceived
}

func (rw *rulesWatcher) doWatchRules(ctx context.Context, _ cell.Health) error {
	select {
	case <-rw.proxySet:
	case <-ctx.Done():
		return ctx.Err()
	}

	for ctx.Err() == nil {
		// First things first: try the SubscribeRules method.
		err := rw.trySubscribeRules(ctx)

		// does the agent not support subscription? Fall back to local gRPC server,
		// but retry if the agent restarts.
		if isUnimplementedError(err) {
			if err := rw.runServer(); err != nil { // launches another goroutine
				return err
			}

			// every 5 minutes, retry subscription
			sctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
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
	rw.stopServer()
	return ctx.Err()
}

// trySubscribeRules connects to the remote agent's gRPC api, issuing
// a SubscribeFQDNRules() call when connected.
//
// It then watches the stream, applying changes to the proxy. Blocks
// until disconnected -- error is never nil.
func (rw *rulesWatcher) trySubscribeRules(ctx context.Context) error {
	rw.log.Info("Trying SubscribeFQDNRules()...")
	rulesStream, err := rw.client.SubscribeFQDNRules(ctx)
	if err != nil {
		return fmt.Errorf("SubscribeFQDNRules failed: %w", err)
	}

	first := true

	for {
		rule, err := rulesStream.Recv()
		if err != nil {
			return fmt.Errorf("SubscribeFQDNRules stream recv error: %w", err)
		}

		// gRPC doesn't actually return meaningful errors until .Recv(), so we don't
		// log until after the first response.
		if first {
			rw.log.Info("Established SubscribeFQDNRules stream")
			first = false
		}

		// It is safe to shut down the gRPC server now; we have a successful rule subscription.
		// noop if already stopped.
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
func (rw *rulesWatcher) runServer() error {
	// Because we periodically re-try to upgrade our connection to the agent,
	// we may call this multiple times. Disregard if already serving.
	if rw.grpcServer != nil {
		return nil
	}

	socket := "/var/run/cilium/proxy.sock"
	os.Remove(socket)
	rw.log.Info("Agent does not support SubscribeFQDNRules(), starting local gRPC server",
		logfields.Socket, socket)

	lis, err := net.Listen("unix", socket)
	if err != nil {
		rw.log.Error("failed to listen", logfields.Error, err)
		return fmt.Errorf("failed to open local gRPC server %s: %w", socket, err)
	}
	var opts []grpc.ServerOption
	rw.grpcServer = grpc.NewServer(opts...)
	pb.RegisterFQDNProxyServer(rw.grpcServer, rw)
	go rw.grpcServer.Serve(lis) // this returns error, but can't actually fail
	return nil
}

// stopServer idempotently stops the local gRPC server.
// not thread safe, only to be called by the doWatchRules goroutine.
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

var _ policy.CachedSelector = &SimpleSelector{}

type SimpleSelector struct {
	identities []identity.NumericIdentity
	name       string
}

func (s *SimpleSelector) GetSelections() identity.NumericIdentitySlice {
	return s.identities
}

func (s *SimpleSelector) GetSelectionsAt(_ policy.SelectorSnapshot) identity.NumericIdentitySlice {
	return s.identities
}

func (s *SimpleSelector) Selects(nid identity.NumericIdentity) bool {
	return slices.Contains(s.identities, nid)
}

func (s *SimpleSelector) IsWildcard() bool {
	return false
}

func (s *SimpleSelector) IsNone() bool {
	return len(s.identities) == 0
}

func (s *SimpleSelector) String() string {
	return s.name
}

func (s *SimpleSelector) GetMetadataLabels() labels.LabelArray {
	return nil
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
