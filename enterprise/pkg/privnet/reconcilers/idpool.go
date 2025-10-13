// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilers

import (
	"errors"
	"math/rand/v2"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/lock"
)

// IDPool handles the allocation of IDs for private networks.
type IDPool struct {
	mu        lock.Mutex
	next, max tables.NetworkID
	used      sets.Set[tables.NetworkID]
}

// NewIDPool creates and returns a new ID pool with custom settings.
func NewIDPool(first, max tables.NetworkID) *IDPool {
	return &IDPool{
		next: first,
		max:  max,
		used: sets.New(tables.NetworkIDReserved),
	}
}

func newDefaultIDPool() *IDPool {
	// Use a random initial value, to make sure we don't incorrectly rely
	// on the fact that network IDs are preserved across restarts.
	return NewIDPool(tables.NetworkID(rand.Uint64N(uint64(tables.NetworkIDMax))+1), tables.NetworkIDMax)
}

func (idp *IDPool) acquire() (tables.NetworkID, error) {
	idp.mu.Lock()
	defer idp.mu.Unlock()

	if idp.used.Len() == int(idp.max)+1 {
		return tables.NetworkIDReserved, errors.New("ID pool exhausted")
	}

	advance := func(cur tables.NetworkID) (next tables.NetworkID) {
		return tables.NetworkID((uint64(cur) + 1) % (uint64(idp.max) + 1))
	}

	cur := idp.next
	for idp.used.Has(cur) {
		cur = advance(cur)
	}

	idp.used.Insert(cur)
	idp.next = advance(cur)
	return cur, nil
}

func (idp *IDPool) release(id tables.NetworkID) {
	// Cannot release the reserved network ID.
	if id != tables.NetworkIDReserved {
		idp.mu.Lock()
		idp.used.Delete(id)
		idp.mu.Unlock()
	}
}
