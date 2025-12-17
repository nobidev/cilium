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
	"context"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
)

// ipcacheAdapter intercepts IPCache metadata updates and forwards any `cidrgroup` labels
// that have been added to a prefix to the CIDRQueuer observer.
type ipcacheAdapter struct {
	upstream policycell.IPCacher
	observer CIDRQueuer

	cidrTracker *CIDRTracker
}

// overridePolicyIPCacher decorates IPCache if the private network feature is enabled
func overridePolicyIPCacher(cfg config.Config, observer CIDRQueuer, ipcache policycell.IPCacher) policycell.IPCacher {
	if !cfg.Enabled {
		return ipcache
	}

	return &ipcacheAdapter{
		upstream:    ipcache,
		observer:    observer,
		cidrTracker: NewCIDRTracker(),
	}
}

func filterLabelsBySource(source string, lbls labels.Labels) labels.Labels {
	out := labels.Labels{}
	for k, v := range lbls {
		if v.Source == source {
			out[k] = v
		}
	}
	return out
}

// UpsertMetadataBatch implements policycell.IPCacher
func (i *ipcacheAdapter) UpsertMetadataBatch(updates ...ipcache.MU) (revision uint64) {
	// Always forward batch to decorated IPCache
	defer func() {
		revision = i.upstream.UpsertMetadataBatch(updates...)
	}()

	// Extract `cidrgroup` labels from IPCache batch
	for _, update := range updates {
		for _, metadata := range update.Metadata {
			lbls, ok := metadata.(labels.Labels)
			if !ok {
				continue // only interested in labels
			}

			owner := update.Resource
			prefix := update.Prefix.AsPrefix()

			if lbls.HasSource(labels.LabelSourceCIDRGroup) {
				// Forward upsert event, but only include `cidrgroup` labels
				i.observer.Queue(EventUpsert, CIDRMetadata{
					Owner:    owner,
					Prefix:   prefix,
					Metadata: CIDRGroupLabels(filterLabelsBySource(labels.LabelSourceCIDRGroup, lbls)),
				})
				i.cidrTracker.Add(owner, prefix)
			} else if i.cidrTracker.Has(owner, prefix) {
				// Resource used to set `cidrgroup` labels, but they have now been removed
				i.observer.Queue(EventDelete, CIDRMetadata{
					Owner:    owner,
					Prefix:   prefix,
					Metadata: CIDRGroupLabels{},
				})
				i.cidrTracker.Remove(owner, prefix)
			}
		}
	}

	return revision
}

// RemoveMetadataBatch implements policycell.IPCacher
func (i *ipcacheAdapter) RemoveMetadataBatch(updates ...ipcache.MU) (revision uint64) {
	defer func() {
		revision = i.upstream.RemoveMetadataBatch(updates...)
	}()

	for _, update := range updates {
		for _, metadata := range update.Metadata {
			_, ok := metadata.(labels.Labels)
			if !ok {
				continue // only interested in labels
			}

			owner := update.Resource
			prefix := update.Prefix.AsPrefix()

			if i.cidrTracker.Has(owner, prefix) {
				i.observer.Queue(EventDelete, CIDRMetadata{
					Owner:    owner,
					Prefix:   prefix,
					Metadata: CIDRGroupLabels{},
				})
				i.cidrTracker.Remove(owner, prefix)
			}
		}
	}

	return revision
}

// WaitForRevision implements policycell.IPCacher
func (i *ipcacheAdapter) WaitForRevision(ctx context.Context, rev uint64) error {
	return i.upstream.WaitForRevision(ctx, rev)
}
