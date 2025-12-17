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
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/pkg/policy"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
	"github.com/cilium/cilium/pkg/policy/types"
)

// policyImportAdapter intercepts policy updates to collect CIDR prefixes found in imported policies.
type policyImportAdapter struct {
	importer    policycell.PolicyImporter
	observer    CIDRQueuer
	cidrTracker *CIDRTracker
}

// overridePolicyImporter decorates the policy importer if the private network feature is enabled
func overridePolicyImporter(cfg config.Config, observer CIDRQueuer, importer policycell.PolicyImporter) policycell.PolicyImporter {
	if !cfg.Enabled {
		return importer
	}

	return &policyImportAdapter{
		importer:    importer,
		observer:    observer,
		cidrTracker: NewCIDRTracker(),
	}
}

// UpdatePolicy implements policycell.PolicyImporter
func (p *policyImportAdapter) UpdatePolicy(update *types.PolicyUpdate) {
	// Always forward policy to decorated importer
	defer p.importer.UpdatePolicy(update)

	// Extract CIDR prefixes from policy
	newPrefixes := sets.New(policy.GetCIDRPrefixes(update.Rules)...)
	oldPrefixes := p.cidrTracker.Swap(update.Resource, newPrefixes)

	toUpsert := newPrefixes.Difference(oldPrefixes)
	toDelete := oldPrefixes.Difference(newPrefixes)

	for prefix := range toUpsert {
		p.observer.Queue(EventUpsert, CIDRMetadata{
			Owner:    update.Resource,
			Prefix:   prefix,
			Metadata: CIDRLabel{},
		})
	}
	for prefix := range toDelete {
		p.observer.Queue(EventDelete, CIDRMetadata{
			Owner:    update.Resource,
			Prefix:   prefix,
			Metadata: CIDRLabel{},
		})
	}
}
