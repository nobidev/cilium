//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package checker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/stream"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/cilium/enterprise/pkg/privnet/health"
	api "github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/api/v1"
	"github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/observers"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	notypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

type (
	// ConnFactoryFn is the type of the function returning a grpc client connection
	// for a given target node.
	ConnFactoryFn func(target tables.INBNode) (*grpc.ClientConn, error)

	// LocalNode identifies the local node.
	LocalNode struct{ Cluster, Name string }
)

func newDefaultConnFactory() ConnFactoryFn {
	return func(target tables.INBNode) (*grpc.ClientConn, error) {
		return grpc.NewClient(
			target.HealthAddress(),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
	}
}

func newDefaultLocalNode(cinfo cmtypes.ClusterInfo) LocalNode {
	return LocalNode{
		Cluster: cinfo.Name,
		Name:    notypes.GetName(),
	}
}

type checker struct {
	*observers.Generic[*health.Event, health.EventKind]

	log     *slog.Logger
	config  config.Config
	factory ConnFactoryFn
	self    LocalNode

	mu        lock.RWMutex
	instances map[tables.INBNode]*instance

	stopping chan struct{}
}

var _ health.Checker = (*checker)(nil)

// New returns a new [health.Checker] instance. Consumers are expected to leverage
// the checker provided via hive, while new instances shall be explicitly created
// for testing purposes only.
func New(log *slog.Logger, lc cell.Lifecycle, cfg config.Config, factory ConnFactoryFn, self LocalNode) health.Checker {
	c := checker{
		Generic: observers.NewGeneric[*health.Event, health.EventKind](),

		log:     log,
		config:  cfg,
		factory: factory,
		self:    self,

		instances: make(map[tables.INBNode]*instance),
		stopping:  make(chan struct{}),
	}

	lc.Append(cell.Hook{OnStop: c.stop})

	return &c
}

// Register implements health.Checker.
func (c *checker) Register(node tables.INBNode, network tables.NetworkName) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	instance, ok := c.instances[node]
	if !ok {
		var err error
		instance, err = c.newInstance(node)

		// Returned errors are unrecoverable (e.g., invalid target IP).
		if err != nil {
			return err
		}

		instance.Start()
		c.instances[node] = instance
	}

	instance.Register(network)
	return nil
}

// Deregister implements health.Checker.
func (c *checker) Deregister(node tables.INBNode, network tables.NetworkName) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	instance, ok := c.instances[node]
	if !ok {
		// Already not registered.
		return nil
	}

	if !instance.Deregister(network) {
		// The last network got deregistered, so we can stop this instance. We
		// don't risk race conditions because are holding the global lock.
		instance.Stop()
		delete(c.instances, node)
	}

	return nil
}

// Activate implements health.Checker.
func (c *checker) Activate(node tables.INBNode, network tables.NetworkName) error {
	c.mu.RLock()
	instance, ok := c.instances[node]
	c.mu.RUnlock()

	if !ok {
		return errors.New("INB is not registered")
	}

	return instance.Activate(network)
}

// Deactivate implements health.Checker.
func (c *checker) Deactivate(node tables.INBNode, network tables.NetworkName) error {
	c.mu.RLock()
	instance, ok := c.instances[node]
	c.mu.RUnlock()

	if !ok {
		return errors.New("INB is not registered")
	}

	return instance.Deactivate(network)
}

// Synced implements health.Checker.
func (c *checker) Synced() {
	c.mu.RLock()
	waits := make([]<-chan struct{}, 0, len(c.instances))
	for _, instance := range c.instances {
		waits = append(waits, instance.Synced())
	}
	c.mu.RUnlock()

	go func() {
		// As a circuit breaker, consider all INBs to be synchronized after
		// timeout expiration, to avoid blocking forever if one is unhealthy.
		timeout := time.After(c.config.Timeout)

		// Wait for all currently registered clusters to sync, before
		// propagating back the synchronization event.
	outer:
		for _, wait := range waits {
			select {
			case <-wait:
			case <-timeout:
				c.log.Warn("Failed to synchronize all INBs before timeout",
					logfields.Timeout, c.config.Timeout,
				)
				break outer
			case <-c.stopping:
				return
			}
		}

		c.Queue(health.EventKindSync, nil)
	}()
}

func (c *checker) stop(_ cell.HookContext) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	close(c.stopping)

	for _, instance := range c.instances {
		instance.Stop()
	}

	c.instances = nil
	return nil
}

type instance struct {
	log *slog.Logger

	wg     sync.WaitGroup
	cancel context.CancelFunc

	synced    chan struct{}
	nodeState atomic.Value
	emit      func(tables.NetworkName, tables.INBNetworkState)

	conn      *grpc.ClientConn
	prober    *prober
	networker *networker
}

func (c *checker) newInstance(node tables.INBNode) (*instance, error) {
	var (
		log  = c.log.With(logfields.Node, node)
		self = api.Node{Cluster: string(c.self.Cluster), Name: string(c.self.Name)}
	)

	conn, err := c.factory(node)
	if err != nil {
		return nil, fmt.Errorf("creating gRPC client: %w", err)
	}

	inst := &instance{
		log: log,

		conn:      conn,
		prober:    newProber(log, c.config, api.NewHealthClient(conn), &self),
		networker: newNetworker(log, c.config, api.NewNetworksClient(conn), &self),

		synced: make(chan struct{}),
	}

	inst.nodeState.Store(tables.INBNodeStateUnknown)
	inst.emit = func(net tables.NetworkName, state tables.INBNetworkState) {
		c.Generic.Queue(health.EventKindUpsert, &health.Event{
			Node: node, Network: net, State: tables.INBHealthState{
				Node: inst.nodeState.Load().(tables.INBNodeState), Network: state,
			},
		})
	}

	return inst, nil
}

func (i *instance) Start() {
	var ctx context.Context
	ctx, i.cancel = context.WithCancel(context.Background())
	i.wg.Go(func() { i.run(ctx) })
}

func (i *instance) Stop() {
	i.cancel()
	i.wg.Wait()

	i.conn.Close()
}

func (i *instance) Synced() <-chan struct{} {
	return i.synced
}

func (i *instance) Register(network tables.NetworkName) {
	i.log.Debug("Registering network", logfields.Network, network)
	i.networker.Register(network)
}

func (i *instance) Deregister(network tables.NetworkName) bool {
	i.log.Debug("Deregistering network", logfields.Network, network)
	return i.networker.Deregister(network)
}

func (i *instance) Activate(network tables.NetworkName) error {
	i.log.Debug("Activating network", logfields.Network, network)
	return i.networker.Activate(network)
}

func (i *instance) Deactivate(network tables.NetworkName) error {
	i.log.Debug("Deactivating network", logfields.Network, network)
	return i.networker.Deactivate(network)
}

func (i *instance) run(ctx context.Context) {
	var wg sync.WaitGroup

	wg.Go(func() { i.prober.Run(ctx) })
	wg.Go(func() { i.proberLoop(ctx) })

	wg.Add(1)
	i.networker.Observe(
		ctx,
		func(nt networkTransition) {
			if nt == networkTransitionSync {
				select {
				case <-i.synced:
				default:
					i.log.Debug("Synchronized")
					close(i.synced)
				}

				return
			}

			i.emit(nt.network, nt.state)
		}, func(error) { wg.Done() },
	)

	wg.Wait()
}

func (i *instance) proberLoop(ctx context.Context) {
	var (
		wg     sync.WaitGroup
		cancel = func() {}
	)

	for transition := range stream.ToChannel(ctx, i.prober) {
		if i.nodeState.Swap(transition) == transition {
			continue
		}

		switch transition {
		case tables.INBNodeStateHealthy:
			var cctx context.Context
			cctx, cancel = context.WithCancel(ctx)
			wg.Go(func() { i.networker.Run(cctx) })

		case tables.INBNodeStateUnhealthy:
			cancel()
			wg.Wait()

			i.networker.ResetToUnknown()
		}
	}

	cancel()
	wg.Wait()
}
