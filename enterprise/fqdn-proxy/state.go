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

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"

	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/version"
)

var startTime = time.Now().Unix()

type stateManager struct {
	log    *slog.Logger
	client *fqdnAgentClient
	db     statedb.DB
	cfg    Config

	agentState statedb.RWTable[tables.AgentState]
	proxyState statedb.RWTable[tables.RemoteProxyState]

	stateUpdates    stream.Observable[stateUpdate]
	sendStateUpdate func(stateUpdate)
	stateDone       func(error)
}

type stateUpdate struct {
	agent tables.AgentState
	proxy tables.RemoteProxyState
}

type stateManagerParams struct {
	cell.In

	Cfg    Config
	Log    *slog.Logger
	JG     job.Group
	Client *fqdnAgentClient

	DB               *statedb.DB
	RemoteProxyState statedb.RWTable[tables.RemoteProxyState]
	AgentState       statedb.RWTable[tables.AgentState]
}

func newStateManager(params stateManagerParams) *stateManager {
	sm := &stateManager{
		log:    params.Log,
		client: params.Client,
		cfg:    params.Cfg,

		db:         *params.DB,
		agentState: params.AgentState,
		proxyState: params.RemoteProxyState,
	}
	sm.stateUpdates, sm.sendStateUpdate, sm.stateDone = stream.Multicast[stateUpdate]()

	params.JG.Add(job.OneShot("sync-state", sm.syncState))

	// if offline mode is disabled, then need to manually transition to live
	if !sm.cfg.EnableOfflineMode {
		params.JG.Add(job.OneShot("mark-proxy-live", sm.markLive))
	}

	return sm
}

func (sm *stateManager) setAgentState(msg *pb.AgentState, offline bool) {
	var state tables.AgentState
	if msg != nil {
		state = tables.AgentStateFromMessage(msg)
	}
	if offline {
		state.Status = pb.AgentStatus_AS_UNSPECIFIED
	}
	wtxn := sm.db.WriteTxn(sm.agentState)
	defer wtxn.Abort()
	if _, _, err := sm.agentState.Insert(wtxn, state); err != nil {
		sm.log.Error("BUG: failed to update agent state", logfields.Error, err)
		return
	}
	sm.log.Info("remote agent changed state", logfields.State, msg)
	sm.onStateChange(wtxn)
	wtxn.Commit()
}

// GetCurrentProxyState returns the currently existing state of the remote proxy.
func (sm *stateManager) GetCurrentProxyState() tables.RemoteProxyState {
	var state tables.RemoteProxyState
	var found bool
	state, _, found = sm.proxyState.Get(sm.db.ReadTxn(), tables.RemoteProxyStateIndex.Query(""))
	if found {
		return state
	}
	state.Status = pb.RemoteProxyStatus_RPS_UNSPECIFIED
	return state
}

// UpdateProxyState records a change in proxy state.
// If `from“ is not UNSPEC, then this will only set the state to `to` if
// already in state `from`.
func (sm *stateManager) UpdateProxyState(from, to pb.RemoteProxyStatus) {
	wtxn := sm.db.WriteTxn(sm.proxyState)
	defer wtxn.Abort()

	// Check existing state.
	existing := pb.RemoteProxyStatus_RPS_UNSPECIFIED
	if old, _, found := sm.proxyState.Get(wtxn, tables.RemoteProxyStateIndex.Query("")); found {
		existing = old.Status
	}

	// If we are already at this state, nothing to do.
	if existing == to {
		return
	}

	// If from is not UNSPEC and existing does not match from, reject this transition
	if from != pb.RemoteProxyStatus_RPS_UNSPECIFIED && from != existing {
		sm.log.Info("Skipped proxy state transition",
			logfields.From, from,
			logfields.To, to,
			logfields.State, existing)
		return
	}

	state := tables.RemoteProxyState{
		Status:            to,
		Version:           version.GetCiliumVersion().Version,
		StartTime:         startTime,
		EnableOfflineMode: sm.cfg.EnableOfflineMode,
	}

	if _, _, err := sm.proxyState.Insert(wtxn, state); err != nil {
		sm.log.Error("BUG: failed to update proxy state", logfields.Error, err)
		return
	}
	sm.log.Info("proxy changed state", logfields.State, to)
	sm.onStateChange(wtxn)
	wtxn.Commit()
}

// onStateChange is called whenever a state is about to be committed and emits
// both the agent and proxy states to all observers.
func (sm *stateManager) onStateChange(txn statedb.ReadTxn) {
	rps, _, ok := sm.proxyState.Get(txn, tables.RemoteProxyStateIndex.Query(""))
	if !ok {
		return
	}
	as, _, ok := sm.agentState.Get(txn, tables.AgentStateIndex.Query(""))
	if !ok {
		return
	}
	sm.sendStateUpdate(stateUpdate{proxy: rps, agent: as})
}

func (sm *stateManager) WatchStateChanges(ctx context.Context) <-chan stateUpdate {
	return stream.ToChannel(ctx, sm.stateUpdates, stream.WithBufferSize(10))
}

// markLive is used when the proxy is not writing to the bpf IPCache directly, and thus
// nothing else is looking for the agent's REGEN -> LIVE transition.
//
// It transitions the proxy from WAITING_FOR_AGENT_LIVE to LIVE when the agent
// itself transitions to LIVE.
func (sm *stateManager) markLive(ctx context.Context, _ cell.Health) error {
	for update := range sm.WatchStateChanges(ctx) {
		if update.agent.Status == pb.AgentStatus_AS_LIVE && update.proxy.Status == pb.RemoteProxyStatus_RPS_WAITING_FOR_AGENT_LIVE {
			sm.UpdateProxyState(pb.RemoteProxyStatus_RPS_WAITING_FOR_AGENT_LIVE, pb.RemoteProxyStatus_RPS_LIVE)
		}
	}
	return ctx.Err()
}

func (sm *stateManager) syncState(ctx context.Context, _ cell.Health) error {
	// initialize states
	sm.setAgentState(nil, true)
	sm.UpdateProxyState(pb.RemoteProxyStatus_RPS_UNSPECIFIED, pb.RemoteProxyStatus_RPS_LIVE)

	var nextLog time.Time

	for {
		err := sm.trySyncState(ctx)
		if ctx.Err() != nil {
			break
		}

		// backoff for up to 1 second, or 5 minutes if agent version is old.
		// immediately retry if gRPC connection state changes.
		retryInterval := time.Second
		if isUnimplementedError(err) {
			// older agent version, every 5 minutes, retry subscription
			retryInterval = 5 * time.Minute
		} else {
			now := time.Now()
			if now.After(nextLog) { // silence needless logs.
				sm.log.Info("error synchronizing state with agent", logfields.Error, err)
				nextLog = now.Add(30 * time.Second)
			}
		}
		sctx, cancel := context.WithTimeout(ctx, retryInterval)
		sm.client.WaitMaybeReconnected(sctx)
		cancel()
	}

	sm.stateDone(ctx.Err())
	return ctx.Err()
}

func (sm *stateManager) trySyncState(ctx context.Context) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(context.Canceled)

	stream, err := sm.client.SubscribeState(ctx)
	if err != nil {
		return fmt.Errorf("SubscribState() failed: %w", err)
	}

	// Launch a goroutine to consume agent states
	go func() {
		var err error
		var agentState *pb.AgentState
		for ctx.Err() == nil {
			agentState, err = stream.Recv()
			if err != nil {
				break
			}
			sm.setAgentState(agentState, false)
		}
		sm.setAgentState(agentState, true)
		cancel(err)
	}()

	// get list/watch of proxy state changes
	wtx := sm.db.WriteTxn(sm.proxyState)
	changeStream, err := sm.proxyState.Changes(wtx)
	wtx.Commit()
	if err != nil {
		sm.log.Error("BUG: failed to watch for proxy state changes", logfields.Error, err)
		return err
	}

	// Forward them to the agent until it fails or we shut down
	for {
		changes, watch := changeStream.Next(sm.db.ReadTxn())
		for change := range changes {
			if err := stream.Send(change.Object.ToMessage()); err != nil {
				sm.log.Info("SubscribeState(): failed to send proxy state change to agent")
				cancel(err)
				return err
			}
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
