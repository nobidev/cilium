//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package health

import (
	"github.com/cilium/stream"

	"github.com/cilium/cilium/enterprise/pkg/privnet/observers"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

// Event represents an healthiness change for a given (INB, network) pair.
type Event struct {
	// Node is the Node this event refers to.
	Node tables.INBNode

	// Network is the private network this event refers to.
	Network tables.NetworkName

	// State is the current state of this pair.
	State tables.INBHealthState
}

// EventKind represents the kind of an healthiness event.
type EventKind string

const (
	EventKindSync   EventKind = "sync"
	EventKindUpsert EventKind = "upsert"
)

// Events represents a sequence of healthiness events.
type Events = observers.Events[*Event, EventKind]

// Checker allows to interact with the health checker, registering/deregistering
// target INBs for probing, and observing health events. All methods shall be non
// blocking (i.e., network operations need to be performed in background), as they
// are expected to be invoked in the context of statedb write transactions.
type Checker interface {
	stream.Observable[Events]

	// Register registers a new (INB, private network) pair for health checking.
	// The underlying implementation may, or may not, take into account the
	// private network (e.g., implement global, per-INB, checks). It is a no-op
	// if the same pair is already registered, and the node IP matches.
	Register(node tables.INBNode, network tables.NetworkName) error

	// Deregister deregisters an (INB, private network) pair for health checking.
	// It is a no-op if the same pair had not been registered before.
	Deregister(node tables.INBNode, network tables.NetworkName) error

	// Activate is called when an INB is to be promoted as the active one for a
	// given network. Implementations may relay this information to the remote
	// INB to allow for proper setup.
	Activate(node tables.INBNode, network tables.NetworkName) error

	// Deactivate is called when an INB is demoted from the active one for a
	// given network. Implementations may relay this information to the remote
	// INB to allow for proper setup. Deactivation is implicit if the INB is
	// no longer healthy or able to serve the given network.
	Deactivate(node tables.INBNode, network tables.NetworkName) error

	// Synced conveys that the initial list of (INB, private network) pairs has
	// been registered, so that the checker can propagate back a synced event
	// once they have been correctly processed.
	Synced()
}
