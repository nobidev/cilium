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
	"github.com/cilium/cilium/enterprise/pkg/privnet/observers"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

type dummy struct {
	*observers.Generic[*Event, EventKind]
}

var _ Checker = (*dummy)(nil)

// NewDummy returns a dummy health checker that simply claims all (INB, network)
// pairs as healthy. Useful for testing purposes.
func NewDummy() Checker {
	return &dummy{
		Generic: observers.NewGeneric[*Event, EventKind](),
	}
}

// Register implements Checker.
func (d *dummy) Register(inb tables.INBNode, network tables.NetworkName) error {
	d.Queue(EventKindUpsert, &Event{Node: inb, Network: network, State: tables.INBHealthState{
		Node: tables.INBNodeStateHealthy, Network: tables.INBNetworkStateConfirmed}})
	return nil
}

// Deregister implements Checker.
func (d *dummy) Deregister(inb tables.INBNode, network tables.NetworkName) error { return nil }

// Activate implements Checker.
func (d *dummy) Activate(node tables.INBNode, network tables.NetworkName) error { return nil }

// Deactivate implements Checker.
func (d *dummy) Deactivate(node tables.INBNode, network tables.NetworkName) error { return nil }

// Synced implements Checker.
func (d *dummy) Synced() {
	d.Queue(EventKindSync, nil)
}
