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
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/dns"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	grpcCodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	grpcStatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/relay"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/time"
)

// fqdnAgentClient holds the gRPC connection and gRPC agent client interface.
type fqdnAgentClient struct {
	pb.FQDNProxyAgentClient
	conn *grpc.ClientConn
	log  *slog.Logger
}

func newAgentClient(log *slog.Logger, jg job.Group) (*fqdnAgentClient, error) {
	conn, err := createClient("unix://" + relay.ProxyRelaySocket)
	if err != nil {
		return nil, fmt.Errorf("failed to create grpc client to talk to agent: %w", err)
	}
	c := &fqdnAgentClient{
		FQDNProxyAgentClient: pb.NewFQDNProxyAgentClient(conn),
		conn:                 conn,
		log:                  log,
	}

	jg.Add(job.OneShot("client-log-transition", c.logStateChanges))

	return c, nil
}

// createClient creates a gRPC client tuned for communication over unix domain sockets, i.e. with
// much more aggressive timeouts than would be suitable for network communication. Note that client
// creation does _not_ perform I/O, hence successful creation of the client does not imply
// connectivity.
func createClient(address string) (*grpc.ClientConn, error) {
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

func (c *fqdnAgentClient) logStateChanges(ctx context.Context, h cell.Health) error {
	for ctx.Err() == nil {
		state := c.conn.GetState()
		if state != connectivity.Idle { // Idle is uninteresting.
			c.log.Info("agent gRPC connection state changed", logfields.State, state)
		}
		if state == connectivity.Idle || state == connectivity.Ready {
			h.OK("gRPC state: " + state.String())
		} else {
			h.Degraded("unhealthy gRPC connection state: "+state.String(), fmt.Errorf("") /*err is required*/)
		}
		c.conn.WaitForStateChange(ctx, state)
	}
	return ctx.Err()
}

// shouldLog evalues the given error, and returns true if it is not a gRPC error
// and the connection is up.
//
// This is used to slience error log spam while the agent is down.
func (c *fqdnAgentClient) shouldLog(err error) bool {
	status, ok := grpcStatus.FromError(err)
	if !ok || status.Code() == grpcCodes.OK || status.Code() == grpcCodes.Unknown {
		return true // not a gRPC error
	}
	return c.conn.GetState() == connectivity.Ready
}

// WaitMaybeConnected waits for the gRPC connection to succeed or ctx to expire.
// Returns true if connected. Note: the connection may immediately go back down!
// This is best-effort, and should only used for pausing a retry-loop for
// a brief (~10 second) period of time.
//
// This is needed because gRPC dial failures do not backoff, instead
// retrying almost instantly. Without this, the proxy needlessly burns CPU
// while the agent is down.
func (c *fqdnAgentClient) WaitMaybeConnected(ctx context.Context) bool {
	for {
		if ctx.Err() != nil {
			return false
		}

		state := c.conn.GetState()
		if state == connectivity.Ready {
			return true
		}
		c.conn.WaitForStateChange(ctx, state)
	}
}

// WaitMaybeReconnected waits for the gRPC connection to go down and back up.
// Use this to detect agent restarts. Returns false if ctx closed.
// Note: Due to details in the internal gRPC state machine (e.g. idle transitions),
// this may return before an actual reconnect has happened. Thus, this is
// best-effort.
func (c *fqdnAgentClient) WaitMaybeReconnected(ctx context.Context) bool {
	state := c.conn.GetState()
	if state == connectivity.Ready {
		c.conn.WaitForStateChange(ctx, connectivity.Ready)
		if ctx.Err() != nil {
			return false
		}
	}
	return c.WaitMaybeConnected(ctx)
}

const DNSNotificationSendRetryInterval = 10 * time.Second
const DNSNotificationSendTimeout = 5 * time.Second

type notifier struct {
	log *slog.Logger
	cfg Config

	client  *fqdnAgentClient
	metrics *notifierMetrics
	queue   chan *pb.DNSNotification
	wg      sync.WaitGroup

	stateManager      *stateManager
	remoteNameManager *remoteNameManager

	// Just used to coalesce log lines
	overflowed atomic.Bool

	// number of queued notifications, so we can detect
	// zero crossing
	pending atomic.Int32
}

type notifierMetrics struct {
	ProxyUpdateErrors   metric.Vec[metric.Counter]
	ProcessingTime      metric.Vec[metric.Observer]
	UpstreamTime        metric.Vec[metric.Observer]
	PolicyTotal         metric.Vec[metric.Counter]
	ProxyUpdateQueueLen metric.GaugeFunc
}

type notifierParams struct {
	cell.In

	Log      *slog.Logger
	Cfg      Config
	LC       cell.Lifecycle
	Registry *metrics.Registry

	Client            *fqdnAgentClient
	StateManager      *stateManager
	RemoteNameManager *remoteNameManager
}

func newNotifier(params notifierParams) *notifier {
	n := &notifier{
		log: params.Log,
		cfg: params.Cfg,

		client:            params.Client,
		stateManager:      params.StateManager,
		remoteNameManager: params.RemoteNameManager,

		queue: make(chan *pb.DNSNotification, params.Cfg.DNSNotificationChannelSize),
	}
	n.metrics = makeNotifierMetrics(n, params.Registry)

	params.LC.Append(n)
	return n
}

func makeNotifierMetrics(n *notifier, reg *metrics.Registry) *notifierMetrics {
	m := &notifierMetrics{
		ProxyUpdateErrors: metric.NewCounterVec(metric.CounterOpts{
			Name:      "update_errors_total",
			Namespace: metricsNamespace,
			Subsystem: "external_dns_proxy",
			Help:      "Number of total cilium DNS notification errors during FQDN IP updates",
		}, []string{"error"}),
		ProcessingTime: metric.NewHistogramVec(metric.HistogramOpts{
			Name:      "processing_duration_seconds",
			Namespace: metricsNamespace,
			Subsystem: "external_dns_proxy",
			Help:      "Seconds spent processing DNS transactions",
		}, []string{"error"}),
		UpstreamTime: metric.NewHistogramVec(metric.HistogramOpts{
			Name:      "upstream_duration_seconds",
			Namespace: metricsNamespace,
			Subsystem: "external_dns_proxy",
			Help:      "Seconds waited to get a reply from a upstream server",
		}, []string{"error"}),
		PolicyTotal: metric.NewCounterVec(metric.CounterOpts{
			Name:      "policy_l7_total",
			Namespace: metricsNamespace,
			Subsystem: "external_dns_proxy",
			Help:      "Number of total proxy requests handled",
		}, []string{"rule"}),
		ProxyUpdateQueueLen: metric.NewGaugeFunc(metric.GaugeOpts{
			Name:      "update_queue_size",
			Namespace: metricsNamespace,
			Subsystem: "external_dns_proxy",
			Help:      "Size of the queue for deferred DNS notifications to the cilium-agent",
		}, func() float64 {
			return float64(n.pending.Load())
		}),
	}

	reg.Register(m.ProxyUpdateErrors)
	reg.Register(m.ProcessingTime)
	reg.Register(m.UpstreamTime)
	reg.Register(m.PolicyTotal)
	reg.Register(m.ProxyUpdateQueueLen)

	return m
}

func (n *notifier) Start(ctx cell.HookContext) error {
	for range n.cfg.DNSNotificationSendWorkers {
		n.wg.Add(1)
		go func() {
			for msg := range n.queue {
				n.sendDNSNotification(context.Background(), msg)
			}
			n.wg.Done()
		}()
	}
	return nil
}

func (n *notifier) Stop(ctx cell.HookContext) error {
	close(n.queue)
	n.wg.Wait()
	return nil
}

const (
	// Metrics labels
	metricErrorTimeout  = "timeout"
	metricErrorProxy    = "proxyErr"
	metricErrorPacking  = "serialization failed"
	metricErrorNoEP     = "noEndpoint"
	metricErrorOverflow = "queueOverflow"
	metricErrorAllow    = "allow"
)

// NotifyOnDNSMsg handles propagating DNS response data
func (n *notifier) NotifyOnDNSMsg(
	lookupTime time.Time,
	ep *endpoint.Endpoint,
	epIPPort string,
	serverID identity.NumericIdentity,
	agentAddr netip.AddrPort,
	msg *dns.Msg,
	protocol string,
	allowed bool,
	stat *dnsproxy.ProxyRequestContext,
) error {
	stat.ProcessingTime.Start()
	metricError := metricErrorAllow
	endMetric := func() {
		success := metricError == metricErrorAllow
		stat.ProcessingTime.End(success)
		n.metrics.UpstreamTime.WithLabelValues(metricError).Observe(
			stat.UpstreamTime.Total().Seconds())
		n.metrics.ProcessingTime.WithLabelValues(metricError).Observe(
			stat.ProcessingTime.Total().Seconds())
	}
	switch {
	case stat.IsTimeout():
		metricError = metricErrorTimeout
		endMetric()
		return nil
	case stat.Err != nil:
		metricError = metricErrorProxy
	}

	n.metrics.PolicyTotal.WithLabelValues("received").Inc()

	if ep == nil {
		metricError = metricErrorNoEP
		endMetric()
		n.log.Error("Endpoint is nil")
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
		n.log.Error("Could not pack dns msg", logfields.Error, err)
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

	_, err = n.client.NotifyOnDNSMessage(ctx, notification)
	if err != nil {
		if n.client.shouldLog(err) {
			n.log.Error("NotifyOnDNSMsg request failed", logfields.Error, err)
		}
		if status, ok := grpcStatus.FromError(err); ok {
			metricError = status.Code().String()
			n.metrics.ProxyUpdateErrors.WithLabelValues(metricError).Inc()
		}

		// Cilium-agent is down or unable to successfully plumb the policy
		// right now, so queue this DNSNotification until cilium is able to
		// handle the message.
		pending := n.pending.Add(1)
		if pending == 1 {
			// We have gone offline! Transition to agent-is-offline state
			n.stateManager.UpdateProxyState(pb.RemoteProxyStatus_RPS_UNSPECIFIED, pb.RemoteProxyStatus_RPS_AGENT_OFFLINE)
		}
		select {
		case n.queue <- notification:
			n.overflowed.Store(false)
		default:
			// reduce pending count, since we're dropping this message on the floor.
			// It is very very very very very unlikely, but this may have been the last pending message,
			// so handle the zero transition here too.
			if n.pending.Add(-1) == 0 {
				n.stateManager.UpdateProxyState(pb.RemoteProxyStatus_RPS_UNSPECIFIED, pb.RemoteProxyStatus_RPS_WAITING_FOR_AGENT_LIVE)
			}
			metricError = metricErrorOverflow
			n.metrics.ProxyUpdateErrors.WithLabelValues(metricErrorOverflow).Inc()
			if n.overflowed.CompareAndSwap(false, true) {
				n.log.Warn("Cilium agent is down and notification channel is full. Skipping notification.")
			}
		}
	}

	// Best effort: try plumping BPF ipcache map while agent is offline (i.e. not in state LIVE).
	if state := n.stateManager.GetCurrentProxyState(); state.Status != pb.RemoteProxyStatus_RPS_LIVE {
		n.remoteNameManager.MaybeUpdateIPCache(msg)
	}

	// Release the DNS response back to the user application. If Cilium
	// previously plumbed the policy for this IP / Name, then the app will
	// successfully connect, regardless of whether Cilium is down or not.
	n.metrics.PolicyTotal.WithLabelValues("forwarded").Inc()
	if msg.Response && msg.Rcode == dns.RcodeSuccess {
		endMetric()
	}
	stat.ProcessingTime.End(true)
	return nil
}

func (n *notifier) sendDNSNotification(ctx context.Context, msg *pb.DNSNotification) {
	for {
		// We are purposefully not backing off exponentially because we want to
		// constantly retry to reach the Agent in case it is down in order to
		// not artificially delay DNS msgs.
		_, err := n.client.NotifyOnDNSMessage(ctx, msg)

		if err != nil {
			// If the endpoint no longer exists, there's no point in sending this mapping.
			var errDNSRequestNoEndpoint dnsproxy.ErrDNSRequestNoEndpoint
			if strings.Contains(err.Error(), errDNSRequestNoEndpoint.Error()) {
				n.log.Debug("Dropping DNS notification since the endpoint no longer exists",
					logfields.Error, err,
					logfields.Address, msg.EpIPPort,
				)
				break
			}
			if n.client.shouldLog(err) {
				n.log.Error("queued NotifyOnDNSMsg request failed", logfields.Error, err)
			}

			// sleep for max 10 seconds, but wake up sooner if the agent reconnects
			sctx, cancel := context.WithTimeout(ctx, DNSNotificationSendRetryInterval)
			n.client.WaitMaybeConnected(sctx)
			cancel()
		} else {
			break
		}
	}

	// connection succeeded
	// Transition to the "flushing queue" state
	n.stateManager.UpdateProxyState(pb.RemoteProxyStatus_RPS_AGENT_OFFLINE, pb.RemoteProxyStatus_RPS_REPLAYING)

	n.log.Debug("Successfully relayed queued DNS notification")

	pending := n.pending.Add(-1)
	if pending == 0 {
		n.stateManager.UpdateProxyState(pb.RemoteProxyStatus_RPS_REPLAYING, pb.RemoteProxyStatus_RPS_WAITING_FOR_AGENT_LIVE)
	}
}
