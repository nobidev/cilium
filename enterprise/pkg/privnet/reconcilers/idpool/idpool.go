// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package idpool

import (
	"errors"
	"io/fs"
	"iter"
	"log/slog"
	"math/rand/v2"
	"path"

	jsoniter "github.com/json-iterator/go"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/wal"
)

// IDPool handles the allocation of IDs for private networks.
type IDPool struct {
	mu          lock.Mutex
	next, max   tables.NetworkID
	allocations map[tables.NetworkName]idAllocation
	used        map[tables.NetworkID]tables.NetworkName

	log       *slog.Logger
	walWriter *wal.Writer[allocationWALEntry]
}

type idAllocation struct {
	id tables.NetworkID
	// restored is true for entries that have been restored from disk and have
	// not been acquired again.
	restored bool
}

// NewIDPool creates and returns a new ID pool with custom settings.
func NewIDPool(log *slog.Logger, first, max tables.NetworkID) *IDPool {
	return &IDPool{
		log:  log,
		mu:   lock.Mutex{},
		next: first,
		max:  max,
		allocations: map[tables.NetworkName]idAllocation{
			"": {
				id: tables.NetworkIDReserved,
			},
		},
		used: map[tables.NetworkID]tables.NetworkName{
			tables.NetworkIDReserved: "",
		},
	}
}

func NewDefaultIDPool(log *slog.Logger, cfg *option.DaemonConfig, lc cell.Lifecycle) *IDPool {
	// Use a random initial value, to make sure we don't incorrectly rely
	// on the fact that network IDs are consitent across nodes
	pool := NewIDPool(log, tables.NetworkID(rand.Uint64N(uint64(tables.NetworkIDMax))+1), tables.NetworkIDMax)
	lc.Append(
		cell.Hook{
			OnStart: func(ctx cell.HookContext) error {
				filePath := path.Join(cfg.StateDir, PrivnetIDWALFile)

				err := pool.restore(filePath)
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						log.Debug("No IDPool WAL found. " +
							"Local Network IDs will not be restored. This might be expected",
						)
					} else {
						log.Warn("Cannot read IDPool WAL."+
							"Local Network IDs will not be restored.",
							logfields.Error, err,
						)
					}
				}

				walw, err := wal.NewWriter[allocationWALEntry](filePath)
				if err != nil {
					log.Warn("Failed to setup IDPool WAL writer."+
						"Local Network IDs will not be preserved.",
						logfields.Error, err,
					)
				}
				pool.walWriter = walw

				return nil
			},
		},
	)
	return pool
}

// Acquire returns a network ID for the provided network name. If a network ID
// was already allocated for the provided network name, the previously
// allocated ID will be returned. acquire will return an error if the ID pool
// was exhausted.
func (idp *IDPool) Acquire(name tables.NetworkName) (tables.NetworkID, error) {
	idp.mu.Lock()
	defer idp.mu.Unlock()

	alloc, ok := idp.allocations[name]
	if ok {
		alloc.restored = false
		idp.allocations[name] = alloc
		return alloc.id, nil
	}

	if len(idp.used) == int(idp.max)+1 {
		return tables.NetworkIDReserved, errors.New("ID pool exhausted")
	}

	advance := func(cur tables.NetworkID) (next tables.NetworkID) {
		return tables.NetworkID((uint64(cur) + 1) % (uint64(idp.max) + 1))
	}

	cur := idp.next
	_, allocated := idp.used[cur]
	for allocated {
		cur = advance(cur)
		_, allocated = idp.used[cur]
	}

	idp.used[cur] = name
	idp.allocations[name] = idAllocation{
		id: cur,
	}

	err := idp.walWrite(allocationWALEntry{
		ID:   cur,
		Name: name,
	})
	if err != nil {
		idp.log.Warn("Failed to write IDPool WAL."+
			"Local Network IDs might not be preserved",
			logfields.Error, err,
		)
	}

	idp.next = advance(cur)

	return cur, nil
}

// Release will free the provided network ID if it was allocated before.
func (idp *IDPool) Release(id tables.NetworkID) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	// Cannot release the reserved network ID.
	if id != tables.NetworkIDReserved {
		name := idp.used[id]
		delete(idp.allocations, name)
		delete(idp.used, id)

		err := idp.walCompact()
		if err != nil {
			idp.log.Warn("Failed to write IDPool WAL."+
				"Local Network IDs might not be preserved",
				logfields.Error, err,
			)
		}
	}
}

// allocationWALEntry is the representation of a single alloction on disk
// STABLE API - make sure not to break backwards compatibility
type allocationWALEntry struct {
	ID   tables.NetworkID
	Name tables.NetworkName
}

func (ae allocationWALEntry) MarshalBinary() (data []byte, err error) {
	return jsoniter.Marshal(ae)
}

const PrivnetIDWALFile = "privnet-net-ids.wal"

func (idp *IDPool) walWrite(e allocationWALEntry) error {
	if idp.walWriter == nil {
		return nil
	}
	return idp.walWriter.Write(e)
}

func (idp *IDPool) walCompact() error {
	if idp.walWriter == nil {
		return nil
	}
	return idp.walWriter.Compact(idp.allWALEntries())
}

func (idp *IDPool) allWALEntries() iter.Seq[allocationWALEntry] {
	return func(yield func(allocationWALEntry) bool) {
		for name, alloc := range idp.allocations {
			if !yield(allocationWALEntry{
				ID:   alloc.id,
				Name: name,
			}) {
				return
			}
		}
	}
}

// restores the checkpoint file content - clearing any in-memory state.
func (idp *IDPool) restore(path string) error {
	allocations, err := wal.Read(path, func(data []byte) (allocationWALEntry, error) {
		var ae allocationWALEntry
		err := jsoniter.Unmarshal(data, &ae)
		return ae, err
	})
	if err != nil {
		return err
	}

	for allocation, err := range allocations {
		if err != nil {
			return err
		}
		idp.allocations[allocation.Name] = idAllocation{
			id:       allocation.ID,
			restored: allocation.ID != tables.NetworkIDReserved,
		}
		idp.used[allocation.ID] = allocation.Name
	}

	return nil
}

// Initialized marks the IDPool as successfully restored and will free any IDs
// that have not been re-acquired. Should only be called once the IDPool has
// seen the "state of the world"
func (idp *IDPool) Initialized() {
	idp.mu.Lock()
	defer idp.mu.Unlock()

	for net, allocation := range idp.allocations {
		if allocation.restored {
			delete(idp.allocations, net)
			delete(idp.used, allocation.id)
		}
	}
	err := idp.walCompact()
	if err != nil {
		idp.log.Warn("Failed to compact IDPool WAL."+
			"Local Network IDs might not be preserved",
			logfields.Error, err,
		)
	}
}
