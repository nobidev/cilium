// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"net/netip"
	"os"
	"strconv"

	"github.com/cilium/dns"
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	"github.com/cilium/cilium/daemon/cmd"
	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	fqdnhaconfig "github.com/cilium/cilium/enterprise/pkg/fqdnha/config"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/doubleproxy"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/tables"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/messagehandler"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	identityCell "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "fqdnha/relay")

type FQDNProxyAgentServer struct {
	pb.UnimplementedFQDNProxyAgentServer

	ctx    context.Context
	cancel context.CancelFunc

	grpcServer *grpc.Server

	daemonPromise   promise.Promise[*cmd.Daemon]
	restorerPromise promise.Promise[endpointstate.Restorer]

	ipCacheGetter   IPCacheGetter
	endpointManager endpointmanager.EndpointManager
	localIDs        stream.Observable[cache.IdentityChange]
	requestHandler  messagehandler.DNSMessageHandler

	db          *statedb.DB
	selectors   statedb.RWTable[FQDNSelector]
	configTable statedb.Table[*tables.ProxyConfig]

	dp *doubleproxy.DoubleProxy
}

type params struct {
	cell.In

	DaemonPromise     promise.Promise[*cmd.Daemon]
	RestorerPromise   promise.Promise[endpointstate.Restorer]
	IPCacheGetter     IPCacheGetter
	EndpointManager   endpointmanager.EndpointManager
	Cfg               fqdnhaconfig.Config
	IdentityAllocator identityCell.CachingIdentityAllocator
	RequestHandler    messagehandler.DNSMessageHandler
	DP                *doubleproxy.DoubleProxy

	DB          *statedb.DB
	Table       statedb.RWTable[FQDNSelector]
	ConfigTable statedb.Table[*tables.ProxyConfig]
}

func (s *FQDNProxyAgentServer) ProvideMappings(stream pb.FQDNProxyAgent_ProvideMappingsServer) error {
	for {
		mapping, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&pb.Success{
				Result: true,
			})
		}
		if err != nil {
			return err
		}

		addr := net.IP(mapping.IP)
		log.Debugf("%s -> %s", mapping.FQDN, addr.String())
	}
}

func (s *FQDNProxyAgentServer) LookupEndpointByIP(ctx context.Context, IP *pb.FQDN_IP) (*pb.Endpoint, error) {
	ip, ok := netip.AddrFromSlice(IP.IP)
	if !ok {
		return &pb.Endpoint{}, fmt.Errorf("unable to convert byte slice %v to netip.Addr", IP.IP)
	}
	ip = ip.Unmap()
	ep := s.endpointManager.LookupIP(ip)
	if ep == nil {
		return &pb.Endpoint{}, fmt.Errorf("cannot find endpoint with IP %s", ip)
	}

	return &pb.Endpoint{
		ID:        uint32(ep.ID),
		Identity:  uint32(ep.SecurityIdentity.ID),
		Namespace: ep.K8sNamespace,
		PodName:   ep.K8sPodName,
	}, nil
}

func (s *FQDNProxyAgentServer) LookupSecurityIdentityByIP(ctx context.Context, IP *pb.FQDN_IP) (*pb.Identity, error) {
	ip, ok := netip.AddrFromSlice(IP.IP)
	if !ok {
		return &pb.Identity{}, fmt.Errorf("unable to convert byte slice %v to netip.Addr", IP.IP)
	}
	id, exists := s.ipCacheGetter.LookupSecIDByIP(ip)
	return &pb.Identity{
		ID:     uint32(id.ID),
		Source: string(id.Source),
		Exists: exists,
	}, nil
}

func (s *FQDNProxyAgentServer) LookupIPsBySecurityIdentity(ctx context.Context, id *pb.Identity) (*pb.IPs, error) {
	ips := s.ipCacheGetter.LookupByIdentity(identity.NumericIdentity(id.ID))

	//TODO: should this not go to string and back to bytes for transfer?
	ipsForTransfer := make([][]byte, len(ips))

	for i, ip := range ips {
		ipsForTransfer[i] = []byte(net.ParseIP(ip))
	}

	return &pb.IPs{
		IPs: ipsForTransfer,
	}, nil
}

func (s *FQDNProxyAgentServer) NotifyOnDNSMessage(ctx context.Context, notification *pb.DNSNotification) (*pb.Empty, error) {
	//TODO: this should probably be factored out into stream of DNS notifications instead of a rpc call per DNS msg

	serverAddrPort, err := netip.ParseAddrPort(notification.ServerAddr)
	if err != nil {
		log.Errorf("Failed to parse server address and port: %s", err)
		return &pb.Empty{}, err
	}

	endpoint, err := s.endpointManager.Lookup(strconv.Itoa(int(notification.Endpoint.ID)))
	if err != nil {
		log.WithField("Endpoint ID", notification.Endpoint.ID).Errorf("Failed to retrieve endpoint")
	}

	dnsMsg := &dns.Msg{}
	err = dnsMsg.Unpack(notification.Msg)
	if err != nil {
		log.Errorf("Failed to unpack DNS message: %s", err)
		return &pb.Empty{}, err
	}

	return &pb.Empty{}, s.requestHandler.NotifyOnDNSMsg(
		notification.Time.AsTime(),
		endpoint,
		notification.EpIPPort,
		identity.NumericIdentity(notification.ServerID),
		serverAddrPort,
		dnsMsg,
		notification.Protocol,
		notification.Allowed,
		&dnsproxy.ProxyRequestContext{DataSource: "external-proxy"})
}

func (s *FQDNProxyAgentServer) SubscribeProxyStatuses(_ *pb.Empty, serverStream grpc.ServerStreamingServer[pb.ProxyStatus]) error {
	log.Info("Streaming proxy status to the external DNS proxy...")
	// Writing to the same gRPC stream from multiple goroutines is not safe.
	stream := &exclusiveStream{
		ServerStreamingServer: serverStream,
	}

	ipVer := pb.IPCacheVersion_One
	err := stream.Send(&pb.ProxyStatus{
		Enum: &ipVer,
	})
	if err != nil {
		log.WithError(err).Infoln("Failed to send ipcache version to proxy.")
		return fmt.Errorf("failed to send ipcache version: %w", err)
	}

	var eg errgroup.Group
	eg.Go(func() error {
		return s.sendSelectors(stream)
	})
	eg.Go(func() error {
		return s.sendIdentities(stream)
	})

	err = eg.Wait()
	if err != nil {
		log.WithError(err).Infof("ProxyStatus stream ended.")
	}
	return nil
}

type statusStream interface {
	Send(m *pb.ProxyStatus) error
	Context() context.Context
}

type exclusiveStream struct {
	mu lock.Mutex
	grpc.ServerStreamingServer[pb.ProxyStatus]
}

func (s *exclusiveStream) Send(m *pb.ProxyStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.ServerStreamingServer.Send(m)
}

func (s *FQDNProxyAgentServer) sendIdentities(stream statusStream) error {
	complete := make(chan error)
	// Subscribe to locally-scoped identities
	ctx, cancel := context.WithCancelCause(stream.Context())
	s.localIDs.Observe(ctx, func(ic cache.IdentityChange) {
		var err error

		switch ic.Kind {
		case cache.IdentityChangeUpsert:
			if ic.Labels == nil || !ic.Labels.HasSource(labels.LabelSourceFQDN) {
				return
			}
			err = stream.Send(&pb.ProxyStatus{
				FqdnIdentity: &pb.FQDNIdentityUpdate{
					Type:     pb.UpdateType_UPDATETYPE_UPSERT,
					Identity: uint64(ic.ID),
					Labels:   fromLabels(ic.Labels),
				},
			})
		case cache.IdentityChangeDelete:
			err = stream.Send(&pb.ProxyStatus{
				FqdnIdentity: &pb.FQDNIdentityUpdate{
					Type:     pb.UpdateType_UPDATETYPE_REMOVE,
					Identity: uint64(ic.ID),
				},
			})
		case cache.IdentityChangeSync:
			err = stream.Send(&pb.ProxyStatus{
				FqdnIdentity: &pb.FQDNIdentityUpdate{
					Type: pb.UpdateType_UPDATETYPE_BOOKMARK,
				},
			})
		default:
			err = fmt.Errorf("unknown identity change type: %+v", ic)
		}
		if err != nil {
			log.WithError(err).Error("Failed to send policy notification to external DNS cache")
			cancel(err)
		}
	}, func(err error) {
		// If we've cancelled the context with an error, this will surface it.
		// If it's a cancelled context, but without a Cause, this will just give
		// us a Cancelled. If that's not the cause for the Observable to call
		// complete, we use whatever is passed to us.
		if cerr := context.Cause(ctx); cerr != nil {
			complete <- cerr
			return
		}
		complete <- err
	})

	return <-complete
}

func (s *FQDNProxyAgentServer) sendSelectors(stream statusStream) error {
	wtx := s.db.WriteTxn(s.selectors)
	selUpdates, err := s.selectors.Changes(wtx)
	defer wtx.Abort()
	if err != nil {
		log.WithError(err).Infoln("BUG: failed to subscribe to the selector table.")
		return err
	}
	rtx := wtx.Commit()
	// Stream what FQDNSelectors are known so far, then send a bookmark.
	it, _ := selUpdates.Next(rtx)
	if err := sendSelectorBatch(stream, it); err != nil {
		return err
	}
	err = stream.Send(&pb.ProxyStatus{
		FqdnSelector: &pb.FQDNSelectorUpdate{
			Type: pb.UpdateType_UPDATETYPE_BOOKMARK,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to send FQDN selector bookmark: %w", err)
	}

	for {
		rtx := s.db.ReadTxn()
		it, selWatch := selUpdates.Next(rtx)
		if err := sendSelectorBatch(stream, it); err != nil {
			return err
		}

		select {
		case <-selWatch:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func sendSelectorBatch(stream statusStream, it iter.Seq2[statedb.Change[FQDNSelector], statedb.Revision]) (err error) {
	for change := range it {
		t := pb.UpdateType_UPDATETYPE_UPSERT
		if change.Deleted {
			t = pb.UpdateType_UPDATETYPE_REMOVE
		}
		err = stream.Send(&pb.ProxyStatus{
			FqdnSelector: &pb.FQDNSelectorUpdate{
				Type: t,
				Selector: &pb.FQDNSelector{
					MatchName:    change.Object.MatchName,
					MatchPattern: change.Object.MatchPattern,
				},
			},
		})
		if err != nil {
			log.WithError(err).Infoln("Failed to send FQDN selector update to proxy.")
			return fmt.Errorf("failed to send fqdn selector update: %w", err)
		}
	}
	return
}

func (s *FQDNProxyAgentServer) GetAllRules(ctx context.Context, empty *pb.Empty) (*pb.RestoredRulesMap, error) {
	// No longer implemented, but return empty map to prevent Unimplemented errors in old (<v1.16) remote proxies
	return &pb.RestoredRulesMap{
		Rules: map[uint64]*pb.RestoredRules{},
	}, nil
}

func fromLabels(lbls labels.Labels) []*pb.Label {
	res := make([]*pb.Label, 0, len(lbls))
	for _, l := range lbls {
		res = append(res, &pb.Label{
			Key:    l.Key,
			Value:  l.Value,
			Source: l.Source,
		})
	}
	return res
}

// SubscribeFQDNRules streams all existing and new FQDNRules from the agent to a remote proxy.
func (s *FQDNProxyAgentServer) SubscribeFQDNRules(stream grpc.BidiStreamingServer[pb.Empty, pb.FQDNRules]) error {
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()

	at := s.dp.RegisterRemote()
	defer s.dp.UnregisterRemote(at)

	wtxn := s.db.WriteTxn(s.configTable)
	changeIter, err := s.configTable.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		log.WithError(err).Error("BUG: failed to watch for ProxyConfig changes")
		return err
	}

	log.Info("SubscribeFQDNRules() stream beginning.")

	for {
		changes, watch := changeIter.Next(s.db.ReadTxn())
		for change, rev := range changes {
			msg := change.Object.ToMsg(change.Deleted)
			log.WithField(logfields.EndpointID, msg.EndpointID).Debug("SubscribeFQDNRules(): forwarding update")
			if err := stream.Send(msg); err != nil {
				// only Info level, as client may have restarted.
				log.WithError(err).Info("SubscribeFQDNRules(): failed to forward update")
				return err
			}
			// Wait for agent to ack rules.
			if _, err := stream.Recv(); err != nil {
				log.WithError(err).Info("SubscribeFQDNRules(): failed to receive response")
				return err
			}
			at.Ack(rev)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-stream.Context().Done():
			return nil
		case <-watch:
		}
	}
}

func NewFQDNProxyAgentServer(
	lc cell.Lifecycle,
	p params,
) *FQDNProxyAgentServer {
	if !p.Cfg.EnableExternalDNSProxy {
		return nil
	}
	s := &FQDNProxyAgentServer{
		daemonPromise:   p.DaemonPromise,
		restorerPromise: p.RestorerPromise,
		ipCacheGetter:   p.IPCacheGetter,
		endpointManager: p.EndpointManager,
		localIDs:        p.IdentityAllocator.LocalIdentityChanges(),
		requestHandler:  p.RequestHandler,
		db:              p.DB,
		selectors:       p.Table,
		configTable:     p.ConfigTable,
		dp:              p.DP,
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	lc.Append(s)
	return s
}

func (s *FQDNProxyAgentServer) Start(ctx cell.HookContext) error {
	_, err := s.daemonPromise.Await(ctx)
	if err != nil {
		return err
	}

	restorer, err := s.restorerPromise.Await(ctx)
	if err != nil {
		return err
	}
	restorer.WaitForEndpointRestore(ctx)

	socket := "/var/run/cilium/proxy-agent.sock"
	os.Remove(socket)
	lis, err := net.Listen("unix", socket)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
		return err
	}
	var opts []grpc.ServerOption
	s.grpcServer = grpc.NewServer(opts...)
	pb.RegisterFQDNProxyAgentServer(s.grpcServer, s)

	log.Info("Starting FQDN relay gRPC server")
	go func() {
		if err := s.grpcServer.Serve(lis); err != nil {
			log.WithError(err).Error("Cannot start FQDN relay gRPC server")
		}
	}()
	return nil
}

func (s *FQDNProxyAgentServer) Stop(ctx cell.HookContext) error {
	log.Info("Stopping FQDN relay gRPC server")
	s.grpcServer.Stop()
	s.cancel()
	return nil
}

type DNSProxyDataSource interface {
	NotifyOnDNSMsg(time.Time, *endpoint.Endpoint, string, identity.NumericIdentity, string, *dns.Msg, string, bool, *dnsproxy.ProxyRequestContext) error
}

type IPCacheGetter interface {
	LookupByIdentity(identity.NumericIdentity) []string
	LookupSecIDByIP(netip.Addr) (ipcache.Identity, bool)
}
