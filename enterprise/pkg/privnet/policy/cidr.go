//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package policy

import (
	"net/netip"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/identity"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
)

type EventKind string

const (
	// EventUpsert is emitted if new metadata associated has been associated with a CIDR
	EventUpsert EventKind = "upsert"
	// EventDelete is emitted if metadata has been removed from a CIDR
	EventDelete EventKind = "delete"
	// EventSynced is emitted if all metadata sources (i.e. CIDRLabel and CIDRGroupLabels)
	// have been synced, i.e. we have observed a complete snapshot of the initial state
	EventSynced EventKind = "synced"
	// EventRestored is emitted after all CIDRRestored events have been emitted
	EventRestored EventKind = "restored"
)

// CIDRQueuer is used to emit events related to CIDR Metadata
type CIDRQueuer interface {
	Queue(EventKind, CIDRMetadata)
}

// CIDRMetadata associates a CIDR prefix with metadata. Every piece of metadata has an owner,
// which is required to upsert and delete the metadata via CIDRQueuer.
// When removing metadata from a prefix, only the correct metadata type has to be provided,
// the concrete contents are ignored for EventDelete.
type CIDRMetadata struct {
	Owner    ipcacheTypes.ResourceID
	Prefix   netip.Prefix
	Metadata CIDRMetadataType
}

// CIDRMetadataType is the interface implemented by all CIDR metadata types
type CIDRMetadataType interface {
	isMetadata() // marker interface
}

// CIDRLabel is a CIDRMetadataType that tells us that the prefix should have a `cidr` label
type CIDRLabel struct{}

func (CIDRLabel) isMetadata() {}

// CIDRGroupLabels is a CIDRMetadataType that tells us that the prefix should have `cidrgroup` labels
type CIDRGroupLabels labels.Labels

func (CIDRGroupLabels) isMetadata() {}

// CIDRRestored is a CIDRMetadataType that tells us that the prefix used to have a particular numeric identity
type CIDRRestored struct {
	Identity identity.NumericIdentity
}

func (CIDRRestored) isMetadata() {}

// CIDRTracker is a helper type that tracks which CIDRs have been added previously by a certain resource
type CIDRTracker struct {
	mu             lock.Mutex
	cidrByResource map[ipcacheTypes.ResourceID]sets.Set[netip.Prefix]
}

// NewCIDRTracker creates a new empty CIDRTracker
func NewCIDRTracker() *CIDRTracker {
	return &CIDRTracker{
		cidrByResource: make(map[ipcacheTypes.ResourceID]sets.Set[netip.Prefix]),
	}
}

// Add associates the cidr with the provided owner
func (c *CIDRTracker) Add(owner ipcacheTypes.ResourceID, cidr netip.Prefix) {
	c.mu.Lock()
	defer c.mu.Unlock()

	set, ok := c.cidrByResource[owner]
	if !ok {
		set = sets.New(cidr)
	} else {
		set = set.Insert(cidr)
	}
	c.cidrByResource[owner] = set
}

// Remove dissociates the cidr with the provided owner
func (c *CIDRTracker) Remove(owner ipcacheTypes.ResourceID, cidr netip.Prefix) {
	c.mu.Lock()
	defer c.mu.Unlock()

	set, ok := c.cidrByResource[owner]
	if !ok {
		return
	}

	set = set.Delete(cidr)
	if len(set) == 0 {
		delete(c.cidrByResource, owner)
	} else {
		c.cidrByResource[owner] = set
	}
}

// Has checks if the provided owner has added this cidr
func (c *CIDRTracker) Has(owner ipcacheTypes.ResourceID, cidr netip.Prefix) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.cidrByResource[owner].Has(cidr)
}

// Swap replaces all cidrs associated with the provided owner and returns the previously associated set of cidrs
func (c *CIDRTracker) Swap(owner ipcacheTypes.ResourceID, new sets.Set[netip.Prefix]) (old sets.Set[netip.Prefix]) {
	c.mu.Lock()
	defer c.mu.Unlock()

	old = c.cidrByResource[owner]
	if len(new) > 0 {
		c.cidrByResource[owner] = new
	} else {
		delete(c.cidrByResource, owner)
	}

	return old
}
