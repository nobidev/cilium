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
	"net/netip"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

type proxyContext struct {
	log               *slog.Logger
	cfg               Config
	client            *fqdnAgentClient
	cache             AgentDataCache
	remoteNameManager *remoteNameManager
}

func newProxyContext(
	log *slog.Logger,
	cfg Config,
	client *fqdnAgentClient,
	remoteNameManager *remoteNameManager,
) *proxyContext {
	return &proxyContext{
		log:               log,
		client:            client,
		cfg:               cfg,
		cache:             NewCache(),
		remoteNameManager: remoteNameManager,
	}
}

func (pc *proxyContext) establishAgentProxyStream() error {
	if !pc.cfg.EnableOfflineMode {
		pc.log.Info(`The proxy status stream from the agent is not needed, because "enable-offline-mode" has been set to false.`)
		return nil
	}
	pc.log.Info("Starting to stream proxy status from the agent...")
	var (
		ps  grpc.ServerStreamingClient[pb.SelectorUpdate]
		err error
	)
	// todo: This method needs more work to reach maturity
	// but until the SubscribeProxyStatus server implementation
	// streams status (rather than just returning on one update)
	// this stub works fine.
	for {
		ps, err = pc.client.SubscribeSelectors(context.Background(), &pb.Empty{})
		if err != nil {
			sts, ok := status.FromError(err)
			// This agent does not support proxy status.
			// Keep checking though in case the agent upgrades.
			if ok && sts.Code() == codes.Unimplemented {
				time.Sleep(time.Minute)
				continue
			}
			return fmt.Errorf("subscribing to selector stream from agent failed: %w", err)
		}

		pc.log.Info("The selector update stream is established.")
		for {
			selectorUpdate, err := ps.Recv()
			if err != nil {
				return fmt.Errorf("error receiving selector update: %w", err)
			}

			pc.remoteNameManager.HandleSelectorUpdate(selectorUpdate)
		}
	}
}

// LookupRegisteredEndpoint wraps logic to lookup an endpoint with any backend.
func (pc *proxyContext) LookupRegisteredEndpoint(ip netip.Addr) (*endpoint.Endpoint, bool, error) {
	// Make sure to send IPv4 addresses as [4]byte instead of [16]byte over gRPC, so they aren't
	// mistakenly treated as IPv6-mapped IPv4 addresses anywhere in the Cilium agent.
	var bs []byte

	if ip.Is4In6() {
		b := ip.As4()
		bs = b[:]
	} else {
		bs = ip.AsSlice()
	}

	ep, err := pc.client.LookupEndpointByIP(context.TODO(), &pb.FQDN_IP{IP: bs})
	if err != nil {
		if pc.client.shouldLog(err) {
			pc.log.Error("LookupEndpointIDByIP request failed", logfields.Error, err)
		}

		pc.cache.lock.RLock()
		endpoint, ok := pc.cache.endpointByIP[ip]
		pc.cache.lock.RUnlock()
		if !ok {
			pc.log.Error("LookupEndpointIDByIP: agent down and endpoint IP not in cache", logfields.IPAddr, ip)
			return nil, false, fmt.Errorf("could not lookup endpoint for ip %s: %w", ip, err)
		}
		pc.log.Debug("LookupEndpointIDByIP: agent down, endpoint IP in cache", logfields.IPAddr, ip)
		return endpoint, false, nil
	}
	endpoint := &endpoint.Endpoint{
		ID: uint16(ep.ID),
		SecurityIdentity: &identity.Identity{
			ID: identity.NumericIdentity(ep.Identity),
		},
		K8sNamespace: ep.Namespace,
		K8sPodName:   ep.PodName,
	}
	pc.cache.lock.Lock()
	pc.cache.endpointByIP[ip] = endpoint
	pc.cache.lock.Unlock()
	return endpoint, false, nil
}

// LookupSecIDByIP wraps logic to lookup an IP's security ID from the
// ipcache.
func (pc *proxyContext) LookupSecIDByIP(ip netip.Addr) (secID ipcache.Identity, exists bool) {
	if !ip.IsValid() {
		return ipcache.Identity{}, false
	}
	var src = source.Unspec
	id, err := pc.remoteNameManager.LookupIPCache(ip)
	if err != nil {
		ident, err := pc.client.LookupSecurityIdentityByIP(context.TODO(), &pb.FQDN_IP{IP: ip.AsSlice()})
		if err != nil {
			if pc.client.shouldLog(err) {
				pc.log.Error("LookupSecIDByIP request failed", logfields.Error, err)
			}

			pc.cache.lock.RLock()
			cachedID, ok := pc.cache.identityByIP[ip]
			pc.cache.lock.RUnlock()
			if !ok {
				pc.log.Error("LookupSecIDByIP: agent down, IP not in cache", logfields.IPAddr, ip)
				return ipcache.Identity{}, false
			}
			// TODO: check if this assumption is correct
			// we assume that the identity exists if it's in the cache
			pc.log.Debug("LookupSecIDByIP: agent down, IP in cache",
				logfields.IPAddr, ip,
				logfields.Identity, secID)
			return cachedID, true
		}

		id = identity.NumericIdentity(ident.ID)
		src = source.Source(ident.Source)
	}

	identity := ipcache.Identity{
		ID:     id,
		Source: src,
	}

	pc.cache.lock.Lock()
	pc.cache.identityByIP[ip] = identity
	pc.cache.lock.Unlock()

	return identity, true
}

// LookupByIdentity wraps logic to lookup an IPs by security ID from the
// ipcache.
func (pc *proxyContext) LookupByIdentity(nid identity.NumericIdentity) []string {
	ips, err := pc.client.LookupIPsBySecurityIdentity(context.TODO(), &pb.Identity{ID: uint32(nid)})
	if err != nil {
		if pc.client.shouldLog(err) {
			pc.log.Error("LookupByIdentity request failed", logfields.Error, err)
		}

		pc.cache.lock.RLock()
		cachedIPs, ok := pc.cache.ipBySecID[nid]
		pc.cache.lock.RUnlock()
		if !ok {
			pc.log.Error("LookupByIdentity: agent down, id not in cache", logfields.Identity, nid)
			return nil
		}

		pc.log.Debug("LookupByIdentity: agent down, id in cache", logfields.Identity, nid)
		return cachedIPs
	}

	result := make([]string, 0, len(ips.IPs))
	for _, ip := range ips.IPs {
		result = append(result, net.IP(ip).String())
	}

	pc.cache.lock.Lock()
	pc.cache.ipBySecID[nid] = result
	pc.cache.lock.Unlock()
	return result
}
