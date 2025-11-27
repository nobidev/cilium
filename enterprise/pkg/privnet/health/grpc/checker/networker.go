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
	"io"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/cilium/stream"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/workqueue"

	api "github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/api/v1"
	"github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// networker implements the logic retrieving the served networks by an INB
// and handling activations/deactivations.
type networker struct {
	log *slog.Logger
	cfg config.Config

	client api.NetworksClient
	self   *api.Node

	running atomic.Bool

	networks networks
	queue    workqueue.TypedDelayingInterface[tables.NetworkName]
}

type networkTransition struct {
	network tables.NetworkName
	state   tables.INBNetworkState
}

// networkTransitionSync is a canary [networkTransition] used to signal synchronization.
var networkTransitionSync = networkTransition{network: "__synced__", state: 255}

func newNetworker(log *slog.Logger, cfg config.Config, cl api.NetworksClient, self *api.Node) *networker {
	return &networker{
		log: log,
		cfg: cfg,

		client: cl,
		self:   self,

		networks: newNetworks(),
	}
}

// Run starts the networker loops, subscribing to the networks channel and
// processing activation/de-activation requests. Run can be invoked again
// after the previous execution terminated, and ResetToUnknown has been called.
func (n *networker) Run(ctx context.Context) {
	if n.running.Swap(true) {
		logging.Panic(n.log, "Cannot start [networker] while still running")
	}

	if n.queue != nil {
		logging.Panic(n.log, "Cannot restart [networker] without resetting it first")
	}

	// Create a new queue instance. It is not protected by a lock, but it is
	// safe under the expected conditions, that is (a) Run is only invoked
	// again once the previous execution terminated, and (b) ResetToUnknown
	// has been invoked in the meanwhile. Indeed, that guarantees that [queue]
	// cannot be possibly accessed while we update it here.
	n.queue = workqueue.NewTypedDelayingQueue[tables.NetworkName]()

	var wg sync.WaitGroup

	wg.Go(func() { n.watchLoop(ctx) })
	wg.Go(func() { n.queueLoop(ctx) })

	wg.Wait()
	n.running.Store(false)
}

// ResetToUnknown resets the networker after that the INB turned unhealthy, marking
// all networks with unknown state. It must be called when Run is not running.
func (n *networker) ResetToUnknown() {
	if n.running.Swap(true) {
		logging.Panic(n.log, "Cannot reset [networker] while still running")
	}

	n.networks.resetToUnknown()

	n.queue = nil
	n.running.Store(false)
}

// Observe allows to observe network state transitions. Emits synthetic transitions
// for already registered networks upon subscription.
func (n *networker) Observe(ctx context.Context, next func(networkTransition), complete func(error)) {
	n.networks.Observe(ctx, next, complete)
}

// Register registers a new locally known private network.
func (n *networker) Register(name tables.NetworkName) {
	n.networks.update(name, func(net *network) { net.registered = true })
}

// Deregister deregisters a previously known private network. It automatically
// triggers its deactivation if it was previously activated. Returns whether
// there's any remaining registered network.
func (n *networker) Deregister(name tables.NetworkName) (remaining bool) {
	var wasActive bool
	n.networks.update(name, func(net *network) {
		net.registered = false
		wasActive, net.active = net.active, false
	})

	if wasActive {
		// This network was previously active, schedule a de-activation.
		n.queue.Add(name)
	}

	// Strictly speaking, this is not fully atomic, because we released the
	// lock above and we acquire it again here. However, the returned value
	// is meaningful only if Register and Deregister calls are serialized,
	// hence, this approach is correct in practice.
	return n.networks.remaining()
}

// Activate queues the request to activate the INB for the given network. It
// returns an error if the network is not registered, or not served by the INB.
func (n *networker) Activate(name tables.NetworkName) error {
	var (
		activate bool
		err      error
	)

	n.networks.update(name, func(net *network) {
		switch {
		case !net.registered:
			err = errors.New("network is not registered")

		case net.state != tables.INBNetworkStateConfirmed:
			err = errors.New("network is not served by INB")

		case !net.active:
			net.active, activate = true, true
		}
	})

	if activate {
		n.queue.Add(name)
	}

	return err
}

// Deactivate queues the request to de-activate the INB for the given network.
// It is a no-op if the network has been de-registered in the meanwhile. It
// returns an error if the network is not registered.
func (n *networker) Deactivate(name tables.NetworkName) error {
	var prev network
	n.networks.update(name, func(net *network) { prev, net.active = *net, false })

	switch {
	case !prev.registered:
		return errors.New("network is not registered")

	case prev.active:
		n.queue.Add(name)
	}

	return nil
}

// watchLoop watches the events about the networks served by the INB.
func (n *networker) watchLoop(ctx context.Context) {
	// Rate limit failure messages, to prevent flooding in case of tight intervals.
	var logrl = rate.NewLimiter(rate.Every(1*time.Minute), 1)

	n.log.Info("Starting watching served networks updates")
	for {
		var incremental bool

		stream, err := n.client.Watch(ctx, &api.WatchRequest{Self: n.self})
		if err != nil {
			if logrl.Allow() {
				n.log.Warn("Failed watching served networks updates. Retrying", logfields.Error, err)
			}
			goto retry
		}

		n.log.Info("Successfully started watching served networks updates")
		for {
			response, err := stream.Recv()
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				break
			}

			st, ok := status.FromError(err)
			if ok && st.Code() == codes.Unavailable {
				n.log.Info("Networks updates stream closed: server is unavailable")
				break
			}

			if err != nil {
				n.log.Warn("Networks updates stream aborted", logfields.Error, err)
				break
			}

			n.log.Debug(
				"Received update of networks served by INB",
				logfields.Count, len(response.GetEvents()),
				logfields.Incremental, incremental,
			)

			var toReplay []tables.NetworkName
			if incremental {
				toReplay = n.networks.handleIncrementalEvents(response.GetEvents())
			} else {
				incremental = true
				toReplay = n.networks.handleEvents(response.GetEvents())
			}

			// Replay the previous activations, in case the INB state got out
			// of sync (e.g., due to a restart).
			for _, name := range toReplay {
				n.queue.Add(name)
			}
		}

	retry:
		select {
		case <-time.After(n.cfg.Interval):
		case <-ctx.Done():
			n.log.Info("Stopping watching served networks updates")
			return
		}
	}
}

// queueLoop processes activation and de-activation requests.
func (n *networker) queueLoop(ctx context.Context) {
	// We never expect persistent failures, because either we succeed or
	// the INB should be declared as unhealthy. However, let's still put
	// an upper bound on retries, and consider the network as denied at
	// that point, to force selecting a different INB as active.
	const maxRetries = 3
	var retries = make(map[tables.NetworkName]uint)

	context.AfterFunc(ctx, n.queue.ShutDown)
	for {
		name, shutdown := n.queue.Get()
		if shutdown {
			return
		}

		// Mark the item done immediately for convenience. That would not be
		// correct if we had multiple workers processing events, but that's
		// not the case here, so it is totally fine.
		n.queue.Done(name)

		var (
			err error
			net = n.networks.get(name)
		)

		op := "activate"
		if !net.active {
			op = "deactivate"
		}

		n.log.Debug("Processing network",
			logfields.Network, name,
			logfields.Operation, op,
		)

		// We expect the parent context to be canceled if the INB turns unhealthy.
		// However, let's also configure an explicit timeout to avoid blocking
		// forever in case the request here blocks, but health checking still works.
		tctx, cancel := context.WithTimeout(ctx, n.cfg.Timeout)
		if net.active {
			err = n.activate(tctx, name)
		} else {
			err = n.deactivate(tctx, name)
		}
		cancel()

		if err == nil {
			n.log.Debug("Successfully processed network",
				logfields.Network, name,
				logfields.Operation, op,
			)

			delete(retries, name)
			continue
		}

		if ctx.Err() != nil {
			// We are terminating
			continue
		}

		retries[name]++
		if retries[name] >= maxRetries {
			n.log.Warn("Failed to process network",
				logfields.Error, err,
				logfields.Network, name,
				logfields.Operation, op,
				logfields.Attempt, retries[name],
			)

			// Something is wrong with this network/INB, let's mark it as denied.
			n.networks.update(name, func(net *network) {
				net.state = tables.INBNetworkStateDenied
				net.active = false
			})

			delete(retries, name)
			continue
		}

		n.log.Warn("Failed to process network, retrying",
			logfields.Error, err,
			logfields.Network, name,
			logfields.Operation, op,
			logfields.Attempt, retries[name],
		)

		// Queue a retry.
		n.queue.AddAfter(name, n.cfg.Interval)
	}
}

// errRemoteRejected is the error returned if the INB rejected the activation or
// de-activation request.
var errRemoteRejected = errors.New("remote INB rejected the request")

func (n *networker) activate(ctx context.Context, name tables.NetworkName) error {
	_, err := n.client.Activate(ctx, &api.ActivationRequest{
		Self: n.self, Network: &api.Network{Name: string(name)},
	})

	st, ok := status.FromError(err)
	if ok && st.Code() == codes.FailedPrecondition {
		return fmt.Errorf("%w: %s", errRemoteRejected, st.Message())
	}

	return err
}

func (n *networker) deactivate(ctx context.Context, name tables.NetworkName) error {
	_, err := n.client.Deactivate(ctx, &api.DeactivationRequest{
		Self: n.self, Network: &api.Network{Name: string(name)},
	})

	return err
}

func (n *networker) active() []tables.NetworkName {
	return n.networks.active()
}

type networks struct {
	mu   lock.RWMutex
	data map[tables.NetworkName]network

	initState tables.INBNetworkState
	synced    bool

	obs  stream.Observable[networkTransition]
	emit func(networkTransition)
}

func newNetworks() networks {
	mcast, emit, _ := stream.Multicast[networkTransition]()

	return networks{
		data: make(map[tables.NetworkName]network),
		obs:  mcast,
		emit: emit,
	}
}

func (n *networks) Observe(ctx context.Context, next func(networkTransition), complete func(error)) {
	// Replay the transitions through a (short lived) goroutine, rather than inline,
	// to make sure that [Observe] is never blocking, regardless of how transitions
	// are then accumulated (e.g., via [stream.ToChannel]). The goroutine immediately
	// terminates when [n.obs.Observe] terminates, which in turn is also non-blocking.
	//
	// However, we grab the lock immediately to ensure that that no new network can
	// be registered before the goroutine starts, making the behavior more predictable.
	n.mu.RLock()
	go func() {
		defer n.mu.RUnlock()

		// Replay synthetic transitions based on the current state.
		for _, entry := range n.data {
			if entry.registered {
				next(networkTransition{network: entry.name, state: entry.state})
			}
		}

		// Replay the synchronization signal, if already synchronized.
		if n.synced {
			next(networkTransitionSync)
		}

		// And finally subscribe to new events. Given that we are still holding
		// the lock, we are guaranteed that no other event got emitted in the
		// meanwhile.
		n.obs.Observe(ctx, next, complete)
	}()
}

func (n *networks) get(name tables.NetworkName) network {
	n.mu.RLock()
	defer n.mu.RUnlock()

	return n.data[name]
}

func (n *networks) update(name tables.NetworkName, mutator func(net *network)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.updateLocked(name, mutator)
}

func (n *networks) updateLocked(name tables.NetworkName, mutator func(net *network)) {
	prev, ok := n.data[name]

	next := prev
	if !ok {
		next = network{name: name, state: n.initState}
	}
	mutator(&next)

	// The entry is no longer registered, nor has been reported as serving by
	// the INB, so we can get rid of it. No need to emit a transition, given
	// is it not registered.
	if !next.registered && next.state != tables.INBNetworkStateConfirmed {
		delete(n.data, name)
		return
	}

	n.data[name] = next

	// No need to emit a transition if (a) the network is not registered, given
	// that we don't care about it, or (b) the state didn't change since the
	// last transition, unless it was already unknown (so that resetToUnknown
	// always emits an event for every entry).
	if !next.registered ||
		(prev.registered && prev.state == next.state && next.state != tables.INBNetworkStateUnknown) {
		return
	}

	n.emit(networkTransition{network: name, state: next.state})
}

func (n *networks) handleEvents(events []*api.NetworkEvents_Event) (toReplay []tables.NetworkName) {
	n.mu.Lock()
	defer n.mu.Unlock()

	var seen = sets.New[tables.NetworkName]()
	for _, event := range events {
		name, shouldReplay := n.handleEventLocked(event)
		seen.Insert(name)
		if shouldReplay {
			toReplay = append(toReplay, name)
		}
	}

	// This is the initial snapshot, make sure to set all networks we have
	// not heard about as denied.
	for name := range n.data {
		if !seen.Has(name) {
			n.updateLocked(name, func(net *network) {
				net.state = tables.INBNetworkStateDenied
				net.active = false
			})
		}
	}

	// We received the initial snapshot, so all subsequently registered
	// networks are assumed to be denied by the remote INB, if not
	// explicitly confirmed.
	n.initState = tables.INBNetworkStateDenied

	// Emit the synchronization transition if this is the first time we
	// receive the full snapshot of networks served by the INB.
	if !n.synced {
		n.synced = true
		n.emit(networkTransitionSync)
	}

	return toReplay
}

func (n *networks) handleIncrementalEvents(events []*api.NetworkEvents_Event) (toReplay []tables.NetworkName) {
	n.mu.Lock()
	defer n.mu.Unlock()

	for _, event := range events {
		if name, shouldReplay := n.handleEventLocked(event); shouldReplay {
			toReplay = append(toReplay, name)
		}
	}

	return toReplay
}

func (n *networks) handleEventLocked(event *api.NetworkEvents_Event) (name tables.NetworkName, shouldReplay bool) {
	name = tables.NetworkName(event.GetNetwork().GetName())
	if name == "" {
		return name, false
	}

	n.updateLocked(name, func(net *network) {
		switch event.GetStatus() {
		case api.NetworkEvents_Event_ACTIVE:
			net.state = tables.INBNetworkStateConfirmed
			// The INB is reporting the network as active, but it is not according
			// to us. Hence, let's replay an explicit deactivation.
			shouldReplay = !net.active
		case api.NetworkEvents_Event_STANDBY:
			net.state = tables.INBNetworkStateConfirmed
			// The INB is reporting the network as standby, but it should be active
			// according to us. Hence, let's replay an explicit activation.
			shouldReplay = net.active
		default:
			net.state = tables.INBNetworkStateDenied
			net.active = false
		}
	})

	return name, shouldReplay
}

func (n *networks) resetToUnknown() {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.initState = tables.INBNetworkStateUnknown
	for name := range n.data {
		n.updateLocked(name, func(net *network) {
			net.state = tables.INBNetworkStateUnknown
			net.active = false
		})
	}
}

func (n *networks) active() []tables.NetworkName {
	var active []tables.NetworkName

	n.mu.RLock()
	defer n.mu.RUnlock()

	for _, entry := range n.data {
		if entry.active {
			active = append(active, entry.name)
		}
	}

	return active
}

func (n *networks) remaining() bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	for _, entry := range n.data {
		if entry.registered {
			return true
		}
	}

	return false
}

type network struct {
	// The name of the network.
	name tables.NetworkName

	// Whether the network is locally known.
	registered bool

	// Whether this network is requested to be active.
	active bool

	// The state of the network, as reported by the INB.
	state tables.INBNetworkState
}
