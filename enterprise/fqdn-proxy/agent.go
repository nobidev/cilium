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

	"github.com/cilium/dns"
	"github.com/cilium/hive/cell"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/time"
)

func newAgentClient(log *slog.Logger) (*fqdnAgentClient, error) {
	conn, err := createClient("unix:///var/run/cilium/proxy-agent.sock")
	if err != nil {
		return nil, fmt.Errorf("failed to create grpc client to talk to agent: %w", err)
	}
	return &fqdnAgentClient{pb.NewFQDNProxyAgentClient(conn)}, nil
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

// fqdnAgentClient holds the gRPC connection and gRPC agent client interface.
type fqdnAgentClient struct {
	pb.FQDNProxyAgentClient
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

	Client *fqdnAgentClient
}

func newNotifier(params notifierParams) *notifier {
	n := &notifier{
		log: params.Log,
		cfg: params.Cfg,

		client: params.Client,
		queue:  make(chan *pb.DNSNotification, params.Cfg.DNSNotificationChannelSize),
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
			return float64(len(n.queue))
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

// NotifyOnDNSMsghandles propagating DNS response data
func (n *notifier) NotifyOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, agentAddr netip.AddrPort, msg *dns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
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
	case allowed, !allowed:
		break
	}

	n.metrics.PolicyTotal.WithLabelValues("received").Inc()

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
	_, err = n.client.NotifyOnDNSMessage(ctx, notification)
	status := updateAgentReachability(err)

	if err != nil {
		if status == nil {
			log.Warn("BUG: Unexpected non-status error during DNS notification to agent", logfields.Error, err)
		} else {
			metricError = status.Code().String()
			n.metrics.ProxyUpdateErrors.WithLabelValues(metricError).Inc()
		}

		// Cilium-agent is down or unable to successfully plumb the policy
		// right now, so queue this DNSNotification until cilium is able to
		// handle the message.
		select {
		case n.queue <- notification:
		default:
			metricError = metricErrorOverflow
			n.metrics.ProxyUpdateErrors.WithLabelValues(metricErrorOverflow).Inc()
			LogWarningTrigger.TriggerWithReason("Cilium agent is down and notification channel is full. Skipping notification.")
		}
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
		requestCtx, cancel := context.WithTimeout(ctx, DNSNotificationSendTimeout)
		_, err := n.client.NotifyOnDNSMessage(requestCtx, msg)
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
