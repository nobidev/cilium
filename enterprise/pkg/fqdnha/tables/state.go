//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tables

import (
	"strconv"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
)

// always empty string
type RemoteProxyStateKey = string

var RemoteProxyStateIndex = statedb.Index[RemoteProxyState, RemoteProxyStateKey]{
	Name: "single-row",
	FromObject: func(obj RemoteProxyState) index.KeySet {
		return index.NewKeySet(index.String(""))
	},
	FromKey:    index.String,
	FromString: index.FromString,
	Unique:     true,
}

// RemoteProxyState mirrors the protobuf type. It's needed as protobufs
// and StateDB don't play well together -- some internal magic prevents copying.
type RemoteProxyState struct {
	Status            pb.RemoteProxyStatus
	Version           string
	StartTime         int64
	EnableOfflineMode bool
}

func RemoteProxyStateFromMessage(msg *pb.RemoteProxyState) RemoteProxyState {
	if msg == nil {
		return RemoteProxyState{}
	}
	return RemoteProxyState{
		Status:            msg.Status,
		Version:           msg.Version,
		StartTime:         msg.StartTime,
		EnableOfflineMode: msg.EnableOfflineMode,
	}
}

func (s *RemoteProxyState) ToMessage() *pb.RemoteProxyState {
	return &pb.RemoteProxyState{
		Status:            s.Status,
		Version:           s.Version,
		StartTime:         s.StartTime,
		EnableOfflineMode: s.EnableOfflineMode,
	}
}

func (s RemoteProxyState) TableHeader() []string {
	return []string{"Status", "Version", "StartTime", "EnableOfflineMode"}
}

func (s RemoteProxyState) TableRow() []string {
	return []string{
		s.Status.String(),
		s.Version,
		strconv.FormatInt(s.StartTime, 10),
		strconv.FormatBool(s.EnableOfflineMode),
	}
}

// The RemoteProxyStateTable stores the current state of the remote (ha) fqdn-proxy.
func NewRemoteProxyStateTable(db *statedb.DB) (statedb.RWTable[RemoteProxyState], statedb.Table[RemoteProxyState], error) {
	tbl, err := statedb.NewTable(
		db,
		"fqdn-remote-proxy-state",
		statedb.Indexer[RemoteProxyState](RemoteProxyStateIndex),
	)
	return tbl, tbl, err
}

// always empty string
type AgentStateKey = string

var AgentStateIndex = statedb.Index[AgentState, AgentStateKey]{
	Name: "single-row",
	FromObject: func(obj AgentState) index.KeySet {
		return index.NewKeySet(index.String(""))
	},
	FromKey:    index.String,
	FromString: index.FromString,
	Unique:     true,
}

// AgentState mirrors the protobuf AgentState type. It is needed as protobuf
// and statedb don't play well together.
type AgentState struct {
	Status            pb.AgentStatus
	Version           string
	IPCacheMapName    string
	StartTime         int64
	EnableOfflineMode bool
}

func AgentStateFromMessage(msg *pb.AgentState) AgentState {
	if msg == nil {
		return AgentState{}
	}
	return AgentState{
		Status:            msg.Status,
		Version:           msg.Version,
		IPCacheMapName:    msg.IPCacheMapName,
		StartTime:         msg.StartTime,
		EnableOfflineMode: msg.EnableOfflineMode,
	}
}

func (s AgentState) ToMessage() *pb.AgentState {
	return &pb.AgentState{
		Status:            s.Status,
		Version:           s.Version,
		IPCacheMapName:    s.IPCacheMapName,
		StartTime:         s.StartTime,
		EnableOfflineMode: s.EnableOfflineMode,
	}
}

func (s AgentState) TableHeader() []string {
	return []string{"Status", "Version", "IPCacheMapName", "StartTime", "EnableOfflineMode"}
}

func (s AgentState) TableRow() []string {
	return []string{
		s.Status.String(),
		s.Version,
		s.IPCacheMapName,
		strconv.FormatInt(s.StartTime, 10),
		strconv.FormatBool(s.EnableOfflineMode),
	}
}

func NewAgentStateTable(db *statedb.DB) (statedb.RWTable[AgentState], statedb.Table[AgentState], error) {
	tbl, err := statedb.NewTable(
		db,
		"fqdn-agent-state",
		statedb.Indexer[AgentState](AgentStateIndex),
	)
	return tbl, tbl, err
}
