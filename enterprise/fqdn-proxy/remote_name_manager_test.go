//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	"github.com/cilium/cilium/pkg/defaults"
	fqdnDNS "github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

func (s *identityStore) len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

func (s *selectorStore) len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.selectors)
}

func TestRemoteNameManagerHandleSelectorUpdate(t *testing.T) {
	r := newRemoteNameManager(
		hivetest.Logger(t),
		Config{
			EnableOfflineMode: true,
		},
	)
	assert.Equal(t, 0, r.identities.len())
	assert.Equal(t, 0, r.selectors.len())

	worldLabel := labels.LabelWorldIPv4[labels.IDNameWorldIPv4]
	id := 42
	su := &pb.SelectorUpdate{
		FqdnIdentity: &pb.FQDNIdentityUpdate{
			Type:     pb.UpdateType_UPDATETYPE_UPSERT,
			Identity: uint64(id),
			Labels: []*pb.Label{
				{
					Source: labels.LabelSourceFQDN,
					Key:    "isovalent.com",
				},
				{
					Source: worldLabel.Source,
					Key:    worldLabel.Key,
				},
			},
		},
	}

	r.HandleSelectorUpdate(su)

	assert.Equal(t, 1, r.identities.len())
	assert.Equal(t, 0, r.selectors.len())

	su = &pb.SelectorUpdate{
		FqdnSelector: &pb.FQDNSelectorUpdate{
			Type: pb.UpdateType_UPDATETYPE_UPSERT,
			Selector: &pb.FQDNSelector{
				MatchName: "isovalent.com",
			},
		},
	}

	r.HandleSelectorUpdate(su)

	assert.Equal(t, 1, r.identities.len())
	assert.Equal(t, 1, r.selectors.len())
}

func TestIdentityStore(t *testing.T) {
	s := newIdentityStore()
	assert.Empty(t, s.byID)
	assert.Empty(t, s.byLabels)

	id := identity.NumericIdentity(42)
	lbls4 := labels.ParseLabelArray("fqdn:isovalent.com", labels.LabelWorldIPv4.String())
	lbls6 := labels.ParseLabelArray("fqdn:isovalent.com", labels.LabelWorldIPv6.String())

	_, ok := s.find(lbls4)
	assert.False(t, ok, "expected to not find identity for %v", lbls4)

	s.upsert(id, lbls4)
	assert.Len(t, s.byID, 1)
	assert.Len(t, s.byLabels, 1)
	got, ok := s.find(lbls4)
	assert.True(t, ok, "expected to find identity for %v", lbls4)
	assert.Equal(t, id, got)

	_, ok = s.find(lbls6)
	assert.False(t, ok, "expected to not find identity for %v", lbls6)

	s.upsert(id, lbls6)
	assert.Len(t, s.byID, 1)
	assert.Len(t, s.byLabels, 1)
	got, ok = s.find(lbls6)
	assert.True(t, ok, "expected to find identity for %v", lbls6)
	assert.Equal(t, id, got)

	s.remove(id)
	_, ok = s.find(lbls4)
	assert.False(t, ok, "expected to not find identity for %v", lbls4)
	_, ok = s.find(lbls6)
	assert.False(t, ok, "expected to not find identity for %v", lbls6)
}

func TestSelectorStore(t *testing.T) {
	s := newSelectorStore(hivetest.Logger(t), Config{FQDNRegexCompileLRUSize: uint(defaults.FQDNRegexCompileLRUSize)})
	assert.Equal(t, 0, s.len())

	fqdnIsovalent := fqdnDNS.FQDN("isovalent.com")

	matches := s.match(fqdnIsovalent)
	assert.Empty(t, matches)

	selector := api.FQDNSelector{
		MatchName: "[a-z]+.com",
	}
	err := s.upsert(selector)
	assert.Error(t, err)
	assert.Equal(t, 0, s.len())

	selector.MatchName = "isovalent.com"
	err = s.upsert(selector)
	assert.NoError(t, err)
	assert.Equal(t, 1, s.len())

	matches = s.match(fqdnIsovalent)
	assert.Len(t, matches, 1)

	fqdnExample := fqdnDNS.FQDN("example.org")

	matches = s.match(fqdnExample)
	assert.Empty(t, matches)

	s.remove(api.FQDNSelector{MatchName: "cilium.io"})
	assert.Equal(t, 1, s.len())
	matches = s.match(fqdnIsovalent)
	assert.Len(t, matches, 1)

	s.remove(api.FQDNSelector{MatchName: "isovalent.com"})
	assert.Equal(t, 0, s.len())
	matches = s.match(fqdnIsovalent)
	assert.Empty(t, matches)
}
