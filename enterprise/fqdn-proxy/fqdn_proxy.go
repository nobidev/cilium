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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/cilium/dns"
	"github.com/cilium/hive/cell"
	"github.com/cilium/workerpool"
	gops "github.com/google/gops/agent"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

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
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ipcacheMap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/pprof"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/cilium/cilium/pkg/version"
)

const (
	metricsNamespace = "isovalent"
)

// slogloggercheck: root logger for fqdn-proxy
var log = logging.DefaultSlogLogger.With(logfields.LogSubsys, "external-dns-proxy")

var (
	proxy     *dnsproxy.DNSProxy
	clientPtr atomic.Pointer[fqdnAgentClient]
	client    = clientPtr.Load
	cache     AgentDataCache
	watcher   *rulesWatcher

	DNSNotificationQueue             chan *pb.DNSNotification
	DNSNotificationSendRetryInterval = 10 * time.Second
	DNSNotificationSendTimeout       = 5 * time.Second

	// Metrics
	defaultSummaryObjectives = map[float64]float64{
		0.5:  0.05,
		0.9:  0.01,
		0.99: 0.001,
	}
	ProxyUpdateErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "update_errors_total",
		Namespace: metricsNamespace,
		Subsystem: "external_dns_proxy",
		Help:      "Number of total cilium DNS notification errors during FQDN IP updates",
	}, []string{"error"})
	ProxyUpdateQueueLen = promauto.NewGauge(prometheus.GaugeOpts{
		Name:      "update_queue_size",
		Namespace: metricsNamespace,
		Subsystem: "external_dns_proxy",
		Help:      "Size of the queue for deferred DNS notifications to the cilium-agent",
	})
	ProcessingTime = promauto.NewSummaryVec(prometheus.SummaryOpts{
		Name:       "processing_duration_seconds",
		Namespace:  metricsNamespace,
		Subsystem:  "external_dns_proxy",
		Help:       "Seconds spent processing DNS transactions",
		Objectives: defaultSummaryObjectives,
	}, []string{"error"})
	UpstreamTime = promauto.NewSummaryVec(prometheus.SummaryOpts{
		Name:       "upstream_duration_seconds",
		Namespace:  metricsNamespace,
		Subsystem:  "external_dns_proxy",
		Help:       "Seconds waited to get a reply from a upstream server",
		Objectives: defaultSummaryObjectives,
	}, []string{"error"})
	PolicyTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "policy_l7_total",
		Namespace: metricsNamespace,
		Subsystem: "external_dns_proxy",
		Help:      "Number of total proxy requests handled",
	}, []string{"rule"})
	Version = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "version",
		Help:      "FQDN Proxy version",
	}, []string{"version"})

	// Metrics labels
	metricErrorTimeout  = "timeout"
	metricErrorProxy    = "proxyErr"
	metricErrorPacking  = "serialization failed"
	metricErrorNoEP     = "noEndpoint"
	metricErrorOverflow = "queueOverflow"
	metricErrorAllow    = "allow"
	LogInfoTrigger      *trigger.Trigger
	LogWarningTrigger   *trigger.Trigger
	LogDebugTrigger     *trigger.Trigger
)

// Encapsulates the FQDNProxyAgentClient behavior but provides
// a concrete type to allow correct usage of atomic.Swap for
// client resets.
type fqdnAgentClient struct {
	pb.FQDNProxyAgentClient
}

func init() {
	var err error
	if LogWarningTrigger, err = trigger.NewTrigger(trigger.Parameters{
		MinInterval: time.Minute,
		TriggerFunc: logTriggerFunc(slog.LevelWarn),
		Name:        "ProxyLogWarning",
	}); err != nil {
		panic(err) // unreachable
	}
	if LogDebugTrigger, err = trigger.NewTrigger(trigger.Parameters{
		MinInterval: time.Minute,
		TriggerFunc: logTriggerFunc(slog.LevelDebug),
		Name:        "DebugLog",
	}); err != nil {
		panic(err) // unreachable
	}
	if LogInfoTrigger, err = trigger.NewTrigger(trigger.Parameters{
		MinInterval: time.Minute,
		TriggerFunc: logTriggerFunc(slog.LevelInfo),
		Name:        "InfoLog",
	}); err != nil {
		panic(err) // unreachable
	}
}

func logTriggerFunc(level slog.Level) func([]string) {
	return func(msgs []string) {
		for _, msg := range msgs {
			log.Log(context.Background(), level, msg)
		}
	}
}

func run(ctx context.Context, health cell.Health, cfg Config) error {
	log.Info("     _ _ _")
	log.Info(" ___|_| |_|_ _ _____")
	log.Info("|  _| | | | | |     |")
	log.Info("|___|_|_|_|___|_|_|_|")
	log.Info("Cilium DNS Proxy", logfields.Version, version.Version)

	log.Info("loaded config options", logfields.Config, cfg)

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.GopsPort)
	if err := gops.Listen(gops.Options{
		Addr:                   addr,
		ReuseSocketAddrAndPort: true,
	}); err != nil {
		log.Error("Cannot start gops server on addr",
			logfields.Address, addr,
			logfields.Error, err,
		)
	}
	defer gops.Close()
	log.Info("Started gops server ", logfields.Address, addr)

	if cfg.EnablePprof {
		pprof.Enable(logging.DefaultSlogLogger, cfg.PprofAddress, int(cfg.PprofPort))
	}

	cache = NewCache()

	go exposeMetrics(cfg)

	DNSNotificationQueue = make(chan *pb.DNSNotification, cfg.DNSNotificationChannelSize)
	conn, err := createClient("unix:///var/run/cilium/proxy-agent.sock")
	if err != nil {
		logging.Fatal(log, "failed to create grpc client to talk to agent", logfields.Error, err)
	}
	clientPtr.Swap(&fqdnAgentClient{pb.NewFQDNProxyAgentClient(conn)})

	go manageDNSNotificationQueue(cfg.DNSNotificationSendWorkers)
	log.Info("starting cilium dns proxy server")
	if err := re.InitRegexCompileLRU(logging.DefaultSlogLogger, int(cfg.FQDNRegexCompileLRUSize)); err != nil {
		logging.Fatal(log, "failed to start DNS proxy: failed to init regex LRU cache", logfields.Error, err)
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

	proxyCtx := newProxyContext(cfg)
	go func() {
		err := proxyCtx.establishAgentProxyStream()
		if err != nil {
			log.Error("Proxy stream error", logfields.Error, err)
		}
	}()

	proxy = dnsproxy.NewDNSProxy(
		dnsProxyConfig,
		proxyCtx,
		LookupEndpointIDByIP,
		NotifyOnDNSMsg,
	)

	watcher = newRulesWatcher(proxy)
	gotRules := watcher.watchRules()

	log.Info("Waiting for agent to provide endpoint configurations...")
	<-gotRules

	log.Info("Got endpoint configurations, opening sockets.")
	err = proxy.Listen(10001)
	if err != nil {
		return fmt.Errorf("failed to start DNS proxy: %w", err)
	}
	log.Info("started dns proxy")
	health.OK("started dns proxy")

	<-ctx.Done()
	return nil
}

type ipCacheLookup interface {
	lookup(netip.Addr) (*ipcacheMap.RemoteEndpointInfo, error)
}

type bpfIPC struct{}

func (ipc *bpfIPC) lookup(addr netip.Addr) (*ipcacheMap.RemoteEndpointInfo, error) {
	log.Debug("real ipcache bpf read for", logfields.Address, addr)
	ipKey := ipcacheMap.NewKey(net.IP(addr.Unmap().AsSlice()), nil, 0)
	// todo: Add IPCacheMap reload logic
	val, err := ipcacheMap.IPCacheMap(nil).Lookup(&ipKey)
	if err != nil {
		return nil, err
	}
	rei, ok := val.(*ipcacheMap.RemoteEndpointInfo)
	if !ok {
		return nil, fmt.Errorf("could not cast ipcache bpf map value (%[1]T) %[1]v to %T", rei, &ipcacheMap.RemoteEndpointInfo{})
	}
	return rei, nil
}

type proxyContext struct {
	cfg       Config
	rwLock    *lock.RWMutex
	ipc       ipCacheLookup
	clientPtr *atomic.Pointer[fqdnAgentClient]

	ipCacheV1 bool
}

func newProxyContext(cfg Config) *proxyContext {
	return &proxyContext{
		ipc:       &bpfIPC{},
		rwLock:    &lock.RWMutex{},
		clientPtr: &clientPtr,
		cfg:       cfg,
	}
}

func (pc *proxyContext) establishAgentProxyStream() error {
	if !(pc.cfg.EnableOfflineMode) {
		log.Info("The proxy status stream from the agent is not needed, because \"enable-offline-mode\" has been set to false.")
		return nil
	}
	log.Info("Starting to stream proxy status from the agent...")
	var (
		ps  grpc.ServerStreamingClient[pb.ProxyStatus]
		err error
	)
	// todo: This method needs more work to reach maturity
	// but until the SubscribeProxyStatus server implementation
	// streams status (rather than just returning on one update)
	// this stub works fine.
	for {
		ps, err = pc.clientPtr.Load().SubscribeProxyStatuses(context.Background(), &pb.Empty{})
		if err != nil {
			sts, ok := status.FromError(err)
			// This agent does not support proxy status.
			// Keep checking though in case the agent upgrades.
			if ok && sts.Code() == codes.Unimplemented {
				time.Sleep(time.Minute)
				continue
			}
			updateAgentReachability(err)
			err = fmt.Errorf("error connecting to stream proxy status: %w", err)
			return err
		}

		log.Info("The agent proxy status stream is established.")
		for {
			agentProxyStatus, err := ps.Recv()
			if err != nil {
				updateAgentReachability(err)
				return fmt.Errorf("error receiving proxy status: %w", err)
			}
			if agentProxyStatus.Enum != nil && *agentProxyStatus.Enum == pb.IPCacheVersion_One {
				pc.rwLock.Lock()
				pc.ipCacheV1 = true
				pc.rwLock.Unlock()
			} else {
				log.Info("got message", logfields.Message, agentProxyStatus)
			}
		}
	}
}

func (pc *proxyContext) supportsIPCacheV1() bool {
	if !(pc.cfg.EnableOfflineMode) {
		return false
	}
	pc.rwLock.RLock()
	defer pc.rwLock.RUnlock()
	return pc.ipCacheV1
}

func manageDNSNotificationQueue(workers uint) {
	wp := workerpool.New(int(workers))
	for msg := range DNSNotificationQueue {
		msg := msg
		ProxyUpdateQueueLen.Dec()
		err := wp.Submit("", func(ctx context.Context) error {
			sendDNSNotification(ctx, msg)
			return nil
		})
		if err != nil {
			log.Error("Error queueing DNS notification", logfields.Error, err)
		}
	}
}

func sendDNSNotification(ctx context.Context, msg *pb.DNSNotification) {
	for {
		// We are purposefully not backing off exponentially because we want to
		// constantly retry to reach the Agent in case it is down in order to
		// not artificially delay DNS msgs.
		requestCtx, cancel := context.WithTimeout(ctx, DNSNotificationSendTimeout)
		_, err := client().NotifyOnDNSMessage(requestCtx, msg)
		cancel()
		updateAgentReachability(err)

		if err != nil {
			// If the endpoint no longer exists, there's no point in sending this mapping.
			var errDNSRequestNoEndpoint dnsproxy.ErrDNSRequestNoEndpoint
			if strings.Contains(err.Error(), errDNSRequestNoEndpoint.Error()) {
				log.Debug("Dropping DNS notification since the endpoint no longer exists",
					logfields.Error, err,
					logfields.Address, msg.EpIPPort,
				)
				return
			}

			time.Sleep(DNSNotificationSendRetryInterval)
			continue
		}

		LogDebugTrigger.TriggerWithReason("Queued DNS Notification was successful")

		return
	}
}

func exposeMetrics(cfg Config) {
	if !cfg.ExposePrometheusMetrics {
		return
	}

	Version.WithLabelValues(version.GetCiliumVersion().Version)
	log.Info("Enabling Prometheus metrics", logfields.Port, cfg.PrometheusPort)
	http.Handle("/metrics", promhttp.Handler())
	err := http.ListenAndServe(fmt.Sprintf(":%d", cfg.PrometheusPort), nil)
	if err != nil {
		log.Error("Failed to enable Prometheus metrics", logfields.Error, err)
	}
}

// createClient creates a gRPC client tuned for communication over unix domain sockets, i.e. with
// much more aggressive timeouts than would be suitable for network communication. Note that client
// creation does _not_ perform I/O, hence successful creation of the client does not imply
// connectivity.
func createClient(address string) (grpc.ClientConnInterface, error) {
	// Override the default backoff config to specify a much shorter base and max delay, since
	// there's no network, no concern of overwhelming a server with many clients nor other problems
	// gRPC tries to be robust against.
	backoff := backoff.Config{
		BaseDelay:  time.Millisecond * 50,
		Multiplier: backoff.DefaultConfig.Multiplier,
		Jitter:     backoff.DefaultConfig.Jitter,
		MaxDelay:   time.Second * 5,
	}

	return grpc.NewClient(address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithIdleTimeout(time.Duration(0)),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff,
			// The MinConnectTimeout comes into play when there is a listener on the unix domain
			// socket, but no server handles incoming connections. This directly impacts DNS tail
			// latency in the worst case, so we're fairly aggressive. After this expires without a
			// successful connection, RPCs fail with "use of closed connection" when started in
			// TRANSIENT_FAILURE, but each still cause an attempt to reestablish a connection after
			// the backoff has been waited for (which we also make much more aggressive).
			MinConnectTimeout: time.Millisecond * 500,
		}),
	)
}

// Tracks whether the agent was reachable the last time we tried a RPC. Serves to avoid logging
// excessively in the expected case of agent downtime (e.g. during upgrades).
var agentReachable atomic.Bool

func updateAgentReachability(err error) *status.Status {
	sts, ok := status.FromError(err)
	if !ok || sts.Code() == codes.OK || sts.Code() == codes.Unknown {
		// Not a gRPC error indicating communication failure, assume agent communication worked.
		if !agentReachable.Swap(true) {
			log.Info("Agent connectivity established.")
			watcher.notifyAgentConnected()
		}
		return sts
	}
	if agentReachable.Swap(false) {
		log.Info("Agent connectivity lost",
			logfields.Code, sts.Code().String(),
			logfields.Error, sts.Message())
	}

	return sts
}

// LookupEndpointIDByIP wraps logic to lookup an endpoint with any backend.
func LookupEndpointIDByIP(ip netip.Addr) (*endpoint.Endpoint, bool, error) {
	// Make sure to send IPv4 addresses as [4]byte instead of [16]byte over gRPC, so they aren't
	// mistakenly treated as IPv6-mapped IPv4 addresses anywhere in the Cilium agent.
	var bs []byte

	if ip.Is4In6() {
		b := ip.As4()
		bs = b[:]
	} else {
		bs = ip.AsSlice()
	}

	ep, err := client().LookupEndpointByIP(context.TODO(), &pb.FQDN_IP{IP: bs})
	updateAgentReachability(err)

	if err != nil {
		cache.lock.RLock()
		endpoint, ok := cache.endpointByIP[ip]
		cache.lock.RUnlock()
		if !ok {
			return nil, false, fmt.Errorf("could not lookup endpoint for ip %s: %w", ip, err)
		}
		LogDebugTrigger.TriggerWithReason(fmt.Sprintf("endpoint retrieved from cache: %s", err))
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
	cache.lock.Lock()
	cache.endpointByIP[ip] = endpoint
	cache.lock.Unlock()
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
		src source.Source = source.Unspec
		err error
	)
	if pc.supportsIPCacheV1() {
		rei, ipcErr := pc.ipc.lookup(ip)
		if ipcErr != nil {
			err = ipcErr
		} else {
			id = identity.NumericIdentity(rei.SecurityIdentity)
		}
	} else {
		var ident *pb.Identity
		ident, err = pc.clientPtr.Load().LookupSecurityIdentityByIP(context.TODO(), &pb.FQDN_IP{IP: ip.AsSlice()})
		updateAgentReachability(err)
		if err == nil {
			id = identity.NumericIdentity(ident.ID)
			src = source.Source(ident.Source)
		}
	}
	if err != nil {
		cache.lock.RLock()
		cachedID, ok := cache.identityByIP[ip]
		cache.lock.RUnlock()
		if !ok {
			log.Error("could not lookup security identity for ip",
				logfields.IPAddr, ip,
				logfields.Error, err)
			return ipcache.Identity{}, false
		}
		// TODO: check if this assumption is correct
		// we assume that the identity exists if it's in the cache
		LogDebugTrigger.TriggerWithReason(fmt.Sprintf("security ID lookup in cache: %s", err))
		return cachedID, true
	}
	identity := ipcache.Identity{
		ID:     id,
		Source: src,
	}

	cache.lock.Lock()
	cache.identityByIP[ip] = identity
	cache.lock.Unlock()

	return identity, true
}

// LookupByIdentity wraps logic to lookup an IPs by security ID from the
// ipcache.
func (*proxyContext) LookupByIdentity(nid identity.NumericIdentity) []string {
	ips, err := client().LookupIPsBySecurityIdentity(context.TODO(), &pb.Identity{ID: uint32(nid)})
	updateAgentReachability(err)

	if err != nil {
		cache.lock.RLock()
		cachedIPs, ok := cache.ipBySecID[nid]
		cache.lock.RUnlock()
		if !ok {
			log.Error("could not lookup ips for id",
				logfields.Identity, nid,
				logfields.Error, err)
			return nil
		}

		LogDebugTrigger.TriggerWithReason(fmt.Sprintf("IPs retrieved from cache: %s", err))
		return cachedIPs
	}

	result := make([]string, 0, len(ips.IPs))
	for _, ip := range ips.IPs {
		result = append(result, net.IP(ip).String())
	}

	cache.lock.Lock()
	cache.ipBySecID[nid] = result
	cache.lock.Unlock()
	return result
}

// NotifyOnDNSMsghandles propagating DNS response data
func NotifyOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, agentAddr netip.AddrPort, msg *dns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
	stat.ProcessingTime.Start()
	metricError := metricErrorAllow
	endMetric := func() {
		success := metricError == metricErrorAllow
		stat.ProcessingTime.End(success)
		UpstreamTime.WithLabelValues(metricError).Observe(
			stat.UpstreamTime.Total().Seconds())
		ProcessingTime.WithLabelValues(metricError).Observe(
			stat.ProcessingTime.Total().Seconds())
	}
	switch {
	case stat.IsTimeout():
		metricError = metricErrorTimeout
		endMetric()
		return nil
	case stat.Err != nil:
		metricError = metricErrorProxy
	case allowed, !allowed:
		break
	}

	PolicyTotal.WithLabelValues("received").Inc()

	if ep == nil {
		metricError = metricErrorNoEP
		endMetric()
		log.Error("Endpoint is nil")
		return errors.New("Endpoint not found")
	}

	endpoint := &pb.Endpoint{
		ID:        uint32(ep.ID),
		Identity:  uint32(ep.SecurityIdentity.ID),
		Namespace: ep.K8sNamespace,
		PodName:   ep.K8sPodName,
	}

	dnsMsg, err := msg.Pack()
	if err != nil {
		metricError = metricErrorPacking
		endMetric()
		log.Error("Could not pack dns msg", logfields.Error, err)
		return err
	}

	notification := &pb.DNSNotification{
		Time:       timestamppb.New(lookupTime),
		Endpoint:   endpoint,
		EpIPPort:   epIPPort,
		ServerAddr: agentAddr.String(),
		Msg:        dnsMsg,
		Protocol:   protocol,
		Allowed:    allowed,
		ServerID:   uint32(serverID),
	}

	// First, try a synchronous policy set up via cilium-agent. If this is
	// successful, we can return and let the DNS socket code handle another
	// request/response.
	ctx, cancel := context.WithTimeout(context.TODO(), time.Duration(DNSNotificationSendTimeout))
	defer cancel()
	_, err = client().NotifyOnDNSMessage(ctx, notification)
	status := updateAgentReachability(err)

	if err != nil {
		if status == nil {
			log.Warn("BUG: Unexpected non-status error during DNS notification to agent", logfields.Error, err)
		} else {
			metricError = status.Code().String()
			ProxyUpdateErrors.WithLabelValues(metricError).Inc()
		}

		// Cilium-agent is down or unable to successfully plumb the policy
		// right now, so queue this DNSNotification until cilium is able to
		// handle the message.
		select {
		case DNSNotificationQueue <- notification:
			ProxyUpdateQueueLen.Inc()
		default:
			metricError = metricErrorOverflow
			ProxyUpdateErrors.WithLabelValues(metricErrorOverflow).Inc()
			LogWarningTrigger.TriggerWithReason("Cilium agent is down and notification channel is full. Skipping notification.")
		}
	}

	// Release the DNS response back to the user application. If Cilium
	// previously plumbed the policy for this IP / Name, then the app will
	// successfully connect, regardless of whether Cilium is down or not.
	PolicyTotal.WithLabelValues("forwarded").Inc()
	if msg.Response && msg.Rcode == dns.RcodeSuccess {
		endMetric()
	}
	stat.ProcessingTime.End(true)
	return nil
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
	for _, id := range s.identities {
		if id == nid {
			return true
		}
	}
	return false
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
