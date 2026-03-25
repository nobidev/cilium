// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"net/netip"

	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	ossTypes "github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/lock"
)

// ErrorPathStore is a store to keep the reference to the paths that could not
// be inserted into the Cilium RIB (the RIB or desired-routes table) due to an
// error. This can be used later for augmenting the output of the CLI command to
// show the paths so that users can users can see the reason why a path is not
// present in the RIB.
//
// The paths are stored in a map with the key being a combination of the
// instance name, and the address family. This reflects the fact that there are
// multiple reconcilers that import routes into the RIB and each reconciler is
// responsible for a specific address family. Each reconcilers can read/write
// the error paths for its own instance and address family.
type ErrorPathStore struct {
	mu         lock.RWMutex
	errorPaths map[instanceFamily]map[ErrorPathKey]ErrorPath
}

func newErrorPathStore() *ErrorPathStore {
	return &ErrorPathStore{
		errorPaths: make(map[instanceFamily]map[ErrorPathKey]ErrorPath),
	}
}

type ErrorPath struct {
	ErrorPathKey
	Error error
}

type ErrorPathKey struct {
	nlri         string
	neighborAddr netip.Addr
}

// Use this constructor to make sure that the key is always constructed in a
// consistent way. This makes sure the Error reporting on the reconcilers side
// and the CLI command side can use the same key to search for the error paths
// in the store.
func ErrorPathKeyFromPath(p *types.ExtendedPath) ErrorPathKey {
	return ErrorPathKey{
		nlri:         p.NLRI.String(),
		neighborAddr: p.NeighborAddr,
	}
}

type instanceFamily struct {
	instance string
	family   ossTypes.Family
}

// Update updates the error paths for a given instance and family. It replaces
// all existing error paths for that instance and family with the new set of
// error paths provided in newPaths. This is because the current implementation
// of the reconcilers recomputes the entire set of paths for each instance and
// family on every reconciliation cycle, so we anyways get the full set of paths
// to be reconciled.
func (eps *ErrorPathStore) Update(instance string, family ossTypes.Family, newPaths map[ErrorPathKey]ErrorPath) {
	eps.mu.Lock()
	defer eps.mu.Unlock()

	ifam := instanceFamily{
		instance: instance,
		family:   family,
	}

	eps.errorPaths[ifam] = newPaths
}

// Delete deletes all error paths for a given instance and family. This is typically
// called when an instance is deleted, so we want to remove all error paths associated
// with that instance and family.
func (eps *ErrorPathStore) Delete(instance string, family ossTypes.Family) {
	eps.mu.Lock()
	defer eps.mu.Unlock()

	delete(eps.errorPaths, instanceFamily{
		instance: instance,
		family:   family,
	})
}

// Get retrieves the error path for a given instance, family, and error path
// key. It returns the error path and a boolean indicating whether the error
// path was found. If the error path is not found, the returned error path will
// be an empty struct and the boolean will be false.
func (eps *ErrorPathStore) Get(instance string, family ossTypes.Family, k ErrorPathKey) (ErrorPath, bool) {
	eps.mu.RLock()
	defer eps.mu.RUnlock()

	ent, found := eps.errorPaths[instanceFamily{
		instance: instance,
		family:   family,
	}]
	if !found {
		return ErrorPath{}, false
	}

	ep, found := ent[k]

	return ep, found
}
