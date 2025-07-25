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
	"slices"

	"github.com/cilium/hive/cell"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	_ "github.com/cilium/cilium/enterprise/fips"
	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"

	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/version"
)

type runParams struct {
	cell.In

	Health     cell.Health
	Cfg        Config
	Log        *slog.Logger
	Watcher    *rulesWatcher
	BPFIPCache bpfIPCache

	Client   *fqdnAgentClient
	Notifier *notifier
}

func run(ctx context.Context, params runParams) error {
	log := params.Log

	log.Info("     _ _ _")
	log.Info(" ___|_| |_|_ _ _____")
	log.Info("|  _| | | | | |     |")
	log.Info("|___|_|_|_|___|_|_|_|")
	log.Info("Cilium DNS Proxy", logfields.Version, version.Version)

	log.Info("loaded config options", logfields.Config, params.Cfg)
	cfg := params.Cfg

	log.Info("starting cilium dns proxy server")
	if err := re.InitRegexCompileLRU(log, int(cfg.FQDNRegexCompileLRUSize)); err != nil {
		return fmt.Errorf("failed to start DNS proxy: failed to init regex LRU cache: %w", err)
	}
	dnsProxyConfig := dnsproxy.DNSProxyConfig{
		Logger:                 log.WithGroup("dns-proxy"),
		Address:                "",
		IPv4:                   cfg.EnableIPV4,
		IPv6:                   cfg.EnableIPV6,
		EnableDNSCompression:   cfg.EnableDNSCompression,
		MaxRestoreDNSIPs:       0,
		ConcurrencyLimit:       int(cfg.ConcurrencyLimit),
		ConcurrencyGracePeriod: cfg.ConcurrencyGracePeriod,
		RejectReply:            cfg.ToFQDNSRejectResponseCode,
	}

	proxyCtx := newProxyContext(log, cfg, params.Client, params.BPFIPCache)
	go func() {
		err := proxyCtx.establishAgentProxyStream()
		if err != nil {
			log.Error("Proxy stream error", logfields.Error, err)
		}
	}()

	proxy := dnsproxy.NewDNSProxy(
		dnsProxyConfig,
		proxyCtx,
		proxyCtx.LookupEndpointIDByIP,
		params.Notifier.NotifyOnDNSMsg,
	)

	// wait for first L7 rules
	gotRules := params.Watcher.waitForRules(proxy)
	log.Info("Waiting for agent to provide endpoint configurations...")
	select {
	case <-gotRules:
	case <-ctx.Done():
		return ctx.Err()
	}
	time.Sleep(2 * time.Second) // grace period to get all endpoints from the agent

	log.Info("Got endpoint configurations, opening sockets.")
	err := proxy.Listen(10001)
	if err != nil {
		return fmt.Errorf("failed to start DNS proxy: %w", err)
	}
	log.Info("started dns proxy")
	params.Health.OK("started dns proxy")

	<-ctx.Done()
	log.Info("Shutting proxy down...")
	proxy.Cleanup()

	return nil
}

type proxyContext struct {
	log    *slog.Logger
	cfg    Config
	ipc    bpfIPCache
	client *fqdnAgentClient
	cache  AgentDataCache

	mu        lock.RWMutex
	ipCacheV1 bool
}

func newProxyContext(
	log *slog.Logger,
	cfg Config,
	client *fqdnAgentClient,
	ipc bpfIPCache,
) *proxyContext {
	return &proxyContext{
		log:    log,
		ipc:    ipc,
		client: client,
		cfg:    cfg,
		cache:  NewCache(),
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
			return fmt.Errorf("SubscribeProxyStatuses failed: %w", err)
		}

		pc.log.Info("The agent proxy status stream is established.")
		for {
			agentProxyStatus, err := ps.Recv()
			if err != nil {
				return fmt.Errorf("error receiving proxy status: %w", err)
			}
			pc.log.Info("got message", logfields.Message, agentProxyStatus)
			// TODO: implement identity + selector streaming
		}
	}
}

func (pc *proxyContext) supportsIPCacheV1() bool {
	if !pc.cfg.EnableOfflineMode {
		return false
	}
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return pc.ipCacheV1
}

// LookupEndpointIDByIP wraps logic to lookup an endpoint with any backend.
func (pc *proxyContext) LookupEndpointIDByIP(ip netip.Addr) (*endpoint.Endpoint, bool, error) {
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
	var (
		id  identity.NumericIdentity
		src = source.Unspec
		err error
	)
	if pc.supportsIPCacheV1() {
		id, err = pc.ipc.lookup(ip)
	} else {
		var ident *pb.Identity
		ident, err = pc.client.LookupSecurityIdentityByIP(context.TODO(), &pb.FQDN_IP{IP: ip.AsSlice()})
		if err == nil {
			id = identity.NumericIdentity(ident.ID)
			src = source.Source(ident.Source)
		}
	}
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

var _ policy.CachedSelector = &SimpleSelector{}

type SimpleSelector struct {
	identities []identity.NumericIdentity
	name       string
}

func (s *SimpleSelector) GetSelections(v *versioned.VersionHandle) identity.NumericIdentitySlice {
	return s.identities
}

func (s *SimpleSelector) Selects(v *versioned.VersionHandle, nid identity.NumericIdentity) bool {
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
