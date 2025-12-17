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
	"context"
	"log/slog"
	"maps"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/observers"
	"github.com/cilium/cilium/enterprise/pkg/privnet/policy"
	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/identity"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var PolicyCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the CIDRMetadata and CIDRIdentity table.
		tables.NewCIDRMetadataTable,
		tables.NewCIDRIdentitiesTable,

		// Provides the CIDR metadata observer consumed by us
		observers.NewGeneric[policy.CIDRMetadata, policy.EventKind],

		newCIDRIdentities,
	),

	cell.Provide(
		// Provides the ReadOnly CIDRMetadata and CIDRIdentity table.
		statedb.RWTable[tables.CIDRMetadata].ToTable,

		// Provides the policy.CIDRQueuer queuing interface
		func(o *observers.Generic[policy.CIDRMetadata, policy.EventKind]) policy.CIDRQueuer {
			return o
		},
	),

	cell.Invoke(
		(*CIDRIdentities).registerCIDRMetadataObserver,
	),
)

// CIDRIdentities is a collection of reconcilers that populates
// the cilium_privnet_cidr_identity BPF map with Cilium identities
// allocated based on collected CIDR metadata.
type CIDRIdentities struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	db       *statedb.DB
	metadata statedb.RWTable[tables.CIDRMetadata]
}

func newCIDRIdentities(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	DB       *statedb.DB
	Metadata statedb.RWTable[tables.CIDRMetadata]
}) *CIDRIdentities {
	return &CIDRIdentities{
		log: in.Log,
		jg:  in.JobGroup,

		cfg: in.Config,

		db:       in.DB,
		metadata: in.Metadata,
	}
}

// registerCIDRMetadataObserver starts a reconciler that watches the CIDRMetadata observer and populates the
// CIDRMetadata table based on the observed associations and disassociations.
func (c *CIDRIdentities) registerCIDRMetadataObserver(observer *observers.Generic[policy.CIDRMetadata, policy.EventKind]) {
	if !c.cfg.Enabled {
		return
	}

	// Only mark the table as initialized when two special events are observed:
	// - policy.EventRestored: The numeric identities from the previous BPF map have been collected.
	//   This ensures that the numeric identity of a CIDR doesn't change between restarts.
	// - policy.EventSynced: Policy ingestion has seen all K8s resources that potentially contain CIDR
	//   rules or CIDRGroups.
	wtx := c.db.WriteTxn(c.metadata)
	identitiesRestored := c.metadata.RegisterInitializer(wtx, "identities-restored")
	cachesSynced := c.metadata.RegisterInitializer(wtx, "caches-synced")
	wtx.Commit()

	c.jg.Add(
		job.Observer(
			"cidr-metadata-observer",
			func(ctx context.Context, buf observers.Events[policy.CIDRMetadata, policy.EventKind]) error {
				wtx := c.db.WriteTxn(c.metadata)
				defer wtx.Commit()

				for _, ev := range buf {
					switch ev.EventKind {
					case policy.EventUpsert:
						c.upsertCIDRMetadata(wtx, ev.Object.Owner, ev.Object.Prefix, ev.Object.Metadata)
					case policy.EventDelete:
						c.deleteCIDRMetadata(wtx, ev.Object.Owner, ev.Object.Prefix, ev.Object.Metadata)
					case policy.EventRestored:
						identitiesRestored(wtx)
					case policy.EventSynced:
						cachesSynced(wtx)
					}
				}

				return nil
			},
			observer,
		),
	)
}

// mergedMetadata associates new CIDR metadata with the owning resource
func mergedMetadata(
	oldOwners map[ipcacheTypes.ResourceID]tables.CIDRMetadataInfo,
	owner ipcacheTypes.ResourceID, metadata policy.CIDRMetadataType,
) (newOwners map[ipcacheTypes.ResourceID]tables.CIDRMetadataInfo) {
	newOwners = maps.Clone(oldOwners)
	if newOwners == nil {
		newOwners = make(map[ipcacheTypes.ResourceID]tables.CIDRMetadataInfo, 1)
	}

	// Overwrite (if metadata has same type as existing info) or merge (if metadata has a different type)
	// metadata in the CIDRMetadataInfo of the owner
	ownerInfo := newOwners[owner]
	switch m := metadata.(type) {
	case policy.CIDRLabel:
		ownerInfo.CIDRLabel = true
	case policy.CIDRGroupLabels:
		ownerInfo.CIDRGroupLabels = labels.Labels(m)
	case policy.CIDRRestored:
		ownerInfo.RestoredIdentity = m.Identity
	}
	newOwners[owner] = ownerInfo

	return newOwners
}

// upsertCIDRMetadata is called when an owner (i.e. a resource) has added or updated
// the metadata associated with a particular prefix.
// We update the CIDRMetadata table accordingly.
func (c *CIDRIdentities) upsertCIDRMetadata(wtx statedb.WriteTxn, owner ipcacheTypes.ResourceID, prefix netip.Prefix, metadata policy.CIDRMetadataType) {
	obj := tables.CIDRMetadata{
		Prefix: prefix,
		Owners: mergedMetadata(nil, owner, metadata),
	}
	c.metadata.Modify(wtx, obj, func(old, new tables.CIDRMetadata) tables.CIDRMetadata {
		old.Owners = mergedMetadata(old.Owners, owner, metadata)
		return old
	})
}

// unmergedMetadata disassociates CIDR metadata from the owning resource.
// Only the type of the disassociated metadata has to be provided.
func unmergedMetadata(
	oldOwners map[ipcacheTypes.ResourceID]tables.CIDRMetadataInfo,
	owner ipcacheTypes.ResourceID, metadata policy.CIDRMetadataType,
) (newOwners map[ipcacheTypes.ResourceID]tables.CIDRMetadataInfo) {
	newOwners = maps.Clone(oldOwners)
	if len(newOwners) == 0 {
		return newOwners
	}

	ownerInfo := oldOwners[owner]
	switch metadata.(type) {
	case policy.CIDRLabel:
		ownerInfo.CIDRLabel = false
	case policy.CIDRGroupLabels:
		ownerInfo.CIDRGroupLabels = nil
	case policy.CIDRRestored:
		ownerInfo.RestoredIdentity = identity.IdentityUnknown
	}

	if ownerInfo.IsEmpty() {
		delete(newOwners, owner)
	} else {
		newOwners[owner] = ownerInfo
	}

	return newOwners
}

// deleteCIDRMetadata is called when an owner (i.e. a resource) has removed
// the metadata associated with a particular prefix.
// We update the CIDRMetadata table accordingly.
func (c *CIDRIdentities) deleteCIDRMetadata(wtx statedb.WriteTxn, owner ipcacheTypes.ResourceID, prefix netip.Prefix, metadata policy.CIDRMetadataType) {
	obj, _, found := c.metadata.Get(wtx, tables.CIDRMetadataByPrefix(prefix))
	if !found {
		c.log.Warn("Observed metadata delete event for unknown prefix",
			logfields.Prefix, prefix,
			logfields.Owner, owner,
		)
		return
	} else if _, ok := obj.Owners[owner]; !ok {
		c.log.Warn("Observed metadata delete event for unknown owner",
			logfields.Prefix, prefix,
			logfields.Owner, owner,
		)
		return
	}

	// Update owners list in object
	obj.Owners = unmergedMetadata(obj.Owners, owner, metadata)
	if len(obj.Owners) == 0 {
		// Last owner removed, remove corresponding entry
		c.metadata.Delete(wtx, obj)
	} else {
		// Upsert object containing updated owners list
		c.metadata.Insert(wtx, obj)
	}
}
