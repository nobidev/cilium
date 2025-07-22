//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package relay

import (
	"context"

	"google.golang.org/grpc"

	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/version"
)

// SubscribeState is a bidirectional stream between the remote (fqdn-ha) proxy and the agent.
//
// When fqdn-ha offline mode is used, both parties must change state in a somewhat lockstep
// fashion. The bidi stream enables that. The remote proxy connects to the agent and both
// parties then push state changes to each other.
//
// The implementation here is tricky; we would like the following to hold:
//   - If the agent is going away, we send a "closing" state to the proxy
//   - If the proxy is going away, we note this fact
//   - If, on the extremely unlikely case that a second connection arrives
//     while an old, stale one was around, we handle this case.
func (s *FQDNProxyAgentServer) SubscribeState(stream grpc.BidiStreamingServer[pb.RemoteProxyState, pb.AgentState]) error {
	// Context for this connection -- closed if the agent is going down
	// or one direction (send / receive) fails.
	ctx, cancel := context.WithCancelCause(s.ctx)
	defer cancel(context.Canceled)

	s.log.Info("SubscribeState() stream beginning.")

	// Handle incoming proxy states
	go func() {
		// Paranoia: there must ever only be one remote proxy connected
		// There could theoretically be a stale connection still shutting down
		// while a new agent starts up. This lock prevents that.
		s.remoteProxyLock.Lock()
		defer s.remoteProxyLock.Unlock()

		var err error
		var proxyState *pb.RemoteProxyState
		// inform the send loop that
		for ctx.Err() == nil {
			proxyState, err = stream.Recv()
			if err != nil {
				break
			}

			s.setRemoteProxyState(proxyState)
		}

		s.log.Info("remote proxy disconnected", logfields.Error, err)
		s.setRemoteProxyState(&pb.RemoteProxyState{})
		cancel(err) // inform sending goroutine that we're done
	}()

	// list/watch agent state, forward this
	wtxn := s.db.WriteTxn(s.agentTable)
	changeStream, err := s.agentTable.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		s.log.Error("BUG: failed to watch for proxy state changes", logfields.Error, err)
		return err
	}

	// Forward changes to the remote proxy
	for {
		changes, watch := changeStream.Next(s.db.ReadTxn())
		for change := range changes {
			if err := stream.Send(change.Object.ToMessage()); err != nil {
				s.log.Info("SubscribeState(): failed to send agent state change to proxy", logfields.Error, err)
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

// setState commits the state of the agent to the statedb table.
func (s *FQDNProxyAgentServer) setState(status pb.AgentStatus) {
	state := tables.AgentState{
		Status:            status,
		Version:           version.GetCiliumVersion().Version,
		StartTime:         startTime,
		IPCacheMapName:    ipcachemap.Name,
		EnableOfflineMode: s.offlineEnabled,
	}
	wtxn := s.db.WriteTxn(s.agentTable)
	defer wtxn.Abort()

	if _, _, err := s.agentTable.Insert(wtxn, state); err != nil {
		s.log.Error("BUG: failed to write agent state", logfields.Error, err)
		return
	}
	s.log.Info("local agent changed state", logfields.State, status)
	wtxn.Commit()
}

// setRemoteProxyState commits the status of the remote proxy to the statedb table.
func (s *FQDNProxyAgentServer) setRemoteProxyState(rps *pb.RemoteProxyState) {
	wtxn := s.db.WriteTxn(s.rpsTable)
	defer wtxn.Abort()

	if _, _, err := s.rpsTable.Insert(wtxn, tables.RemoteProxyStateFromMessage(rps)); err != nil {
		s.log.Error("BUG: failed to write remote proxy state", logfields.Error, err)
		return
	}
	s.log.Info("remote proxy changed state", logfields.State, rps.Status)
	wtxn.Commit()
}

// waitRemoteProxyReplayed waits for a remote proxy to connect and enter state LIVE or WAITING_FOR_AGENT_LIVE.
// It will wait a maximum of 15 seconds for resiliency purposes. (A few dropped packets are
// preferable to an agent permanently blocked from starting up).
//
// This is to allow a remote proxy to reconnect and replay any pending DNS messages. It is used
// with fqdnha offline mode to ensure that endpoints do not experience any drops while being regenerated.
// Otherwise, there may be a newly-learned IP in the outgoing ipcache and the replay queue.
func (s *FQDNProxyAgentServer) waitRemoteProxyReplayed(ctx context.Context) error {
	if !s.offlineEnabled {
		return nil
	}

	s.log.Info("FQDN-HA offline mode enabled. Blocking regeneration up to 15 seconds for remote proxy to replay any queued DNS messages.")
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	proxyStatus, err := tables.WaitForRemoteProxyStatus(ctx, s.db, s.rpsTable, pb.RemoteProxyStatus_RPS_WAITING_FOR_AGENT_LIVE, pb.RemoteProxyStatus_RPS_LIVE)
	if err == nil {
		s.log.Info("Remote proxy has finished replaying DNS messages, proceeding with regeneration")
	} else {
		if proxyStatus == pb.RemoteProxyStatus_RPS_UNSPECIFIED {
			s.log.Info("FQDN-HA offine mode enabled, but remote proxy did did not send a state. Proceeding.")
		} else {
			s.log.Warn("FQDN-HA offline mode enabled, but remote proxy did not reach state LIVE or WAITING_FOR_AGENT_LIVE before deadline",
				logfields.State, proxyStatus)
		}
	}
	return nil
}

var startTime = time.Now().Unix()
