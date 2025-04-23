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
	"net"
	"os"
	"regexp"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"
)

type rulesWatcher struct {
	grpcServer *grpc.Server

	proxy          *dnsproxy.DNSProxy
	agentConnected chan struct{}

	muteErrors bool // if true, don't log subsequent reconnects
}

func newRulesWatcher(proxy *dnsproxy.DNSProxy) *rulesWatcher {
	return &rulesWatcher{
		proxy:          proxy,
		agentConnected: make(chan struct{}),
	}
}

type FQDNProxyServer struct {
	pb.UnimplementedFQDNProxyServer

	proxy *dnsproxy.DNSProxy
}

// watchRules plumbs the rule pipeline from the agent to the proxy.
// Rules are the set of allowed FQDNs a given endpoint is allowed to query.
func (rw *rulesWatcher) watchRules() {
	for {
		// First things first: try the SubscribeRules method.
		err := rw.trySubscribeRules()

		// does the agent not support subscription? Fall back to local gRPC server,
		// but retry if the agent restarts.
		if isUnimplementedError(err) {
			log.Info("Agent does not support SubscribeFQDNRules(), falling back to gRPC server.")
			rw.runServer(rw.proxy) // launches another goroutine
			<-rw.agentConnected    // wait to see if the agent is connected
		} else if err != nil {
			if !rw.muteErrors {
				log.WithError(err).Infof("SubscribeFQDNRules() request failed")
				rw.muteErrors = true // unset on successful connect
			}
			time.Sleep(500 * time.Millisecond) // connection failed, pause then retry
		}
	}
}

// trySubscribeRules connects to the remote agent's gRPC api, issuing
// a SubscribeFQDNRules() call when connected.
//
// It then watches the stream, applying changes to the proxy. Blocks
// until disconnected -- error is never nil.
func (rw *rulesWatcher) trySubscribeRules() error {
	rulesStream, err := client().SubscribeFQDNRules(context.Background())
	if err != nil {
		return fmt.Errorf("SubscribeFQDNRules failed: %w", err)
	}

	rw.muteErrors = false
	log.Info("Established SubscribeFQDNRules stream")

	for {
		rule, err := rulesStream.Recv()
		if err != nil {
			return fmt.Errorf("SubscribeFQDNRules stream recv error: %w", err)
		}

		// It is safe to shut down the gRPC server now; we have a successful rule subscription
		// noop if already stopped
		rw.stopServer()

		err = updateAllowed(proxy, rule)
		if err != nil {
			log.WithError(err).Error("Failed to apply invalid rule to proxy")
		}
		err = rulesStream.Send(&pb.Empty{}) // ack the rule
		if err != nil {
			return fmt.Errorf("SubscribeFQDNRules stream send error: %w", err)
		}
	}
}

// notifyAgentConnected is called when the FQDN proxy notices
// that we've connected to the agent.
//
// It is used to try and transition back to the modern SubscribeRules api
func (rw *rulesWatcher) notifyAgentConnected() {
	if rw == nil {
		return
	}

	select {
	case rw.agentConnected <- struct{}{}:
	default:
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
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	rw.grpcServer = grpc.NewServer(opts...)
	fqdnps := &FQDNProxyServer{proxy: proxy}
	pb.RegisterFQDNProxyServer(rw.grpcServer, fqdnps)
	go rw.grpcServer.Serve(lis)
}

func (rw *rulesWatcher) stopServer() {
	if rw.grpcServer == nil {
		return
	}

	rw.grpcServer.GracefulStop()
	rw.grpcServer = nil
}

func (s *FQDNProxyServer) UpdateAllowed(ctx context.Context, rules *pb.FQDNRules) (*pb.Empty, error) {
	err := updateAllowed(s.proxy, rules)
	return &pb.Empty{}, err
}

func (s *FQDNProxyServer) RemoveRestoredRules(ctx context.Context, endpointIDMsg *pb.EndpointID) (*pb.Empty, error) {
	// noop, but implemented so that agents don't see an error.
	return &pb.Empty{}, nil
}

func (s *FQDNProxyServer) GetRules(ctx context.Context, endpointIDMsg *pb.EndpointID) (*pb.RestoredRules, error) {
	// noop, never actually called by the agent, return empty result
	return &pb.RestoredRules{}, nil

}

func updateAllowed(proxy *dnsproxy.DNSProxy, rules *pb.FQDNRules) error {
	var portProto restore.PortProto
	if rules.DestProto == 0 {
		portProto = restore.PortProto(rules.DestPort)
	} else {
		portProto = restore.MakeV2PortProto(uint16(rules.DestPort), u8proto.U8proto(rules.DestProto))
	}

	log.WithFields(logrus.Fields{
		logfields.Endpoint: rules.EndpointID,
		logfields.Port:     portProto.Port(),
		logfields.Protocol: portProto.Protocol(),
		logfields.Count:    len(rules.Rules.SelectorRegexMapping),
	}).Info("Updating rules for endpoint")

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

	return proxy.UpdateAllowedFromSelectorRegexes(rules.EndpointID, portProto, cachedSelectorREEntry)
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
