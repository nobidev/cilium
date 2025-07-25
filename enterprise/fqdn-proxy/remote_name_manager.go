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
	"log/slog"
	"regexp"

	pb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
)

type remoteNameManager struct {
	logger *slog.Logger

	cfg Config

	identities *identityStore
	selectors  *selectorStore
}

func newRemoteNameManager(logger *slog.Logger, cfg Config) *remoteNameManager {
	return &remoteNameManager{
		logger:     logger,
		cfg:        cfg,
		identities: newIdentityStore(),
		selectors:  newSelectorStore(logger, cfg),
	}
}

func (r *remoteNameManager) HandleSelectorUpdate(su *pb.SelectorUpdate) {
	r.logger.Debug("got selector update message", logfields.Message, su)

	if fqdnIdentity := su.GetFqdnIdentity(); fqdnIdentity != nil {
		r.updateFQDNIdentity(fqdnIdentity)
	} else if fqdnSelector := su.GetFqdnSelector(); fqdnSelector != nil {
		r.updateFQDNSelector(fqdnSelector)
	} else {
		r.logger.Warn("unknown message, ignoring", logfields.Message, su)
	}
}

func (r *remoteNameManager) updateFQDNIdentity(m *pb.FQDNIdentityUpdate) {
	switch m.Type {
	case pb.UpdateType_UPDATETYPE_UPSERT:
		id := identity.NumericIdentity(m.GetIdentity())
		// We don't care about identities which are not pure FQDN identities.
		if lbls := extractLabels(m.GetLabels()); lbls != nil {
			r.identities.upsert(id, lbls)
		} else {
			// Make sure that we don't keep an old variant of this ID alive.
			r.identities.remove(id)
		}
	case pb.UpdateType_UPDATETYPE_REMOVE:
		r.identities.remove(identity.NumericIdentity(m.GetIdentity()))
	case pb.UpdateType_UPDATETYPE_BOOKMARK:
		// TODO
	default:
		r.logger.Warn("Unknown FQDN identity update type", logfields.Type, m.Type)
	}
}

type identityStore struct {
	mu lock.RWMutex

	byID     map[identity.NumericIdentity]labels.LabelArray
	byLabels map[labelsKey]identity.NumericIdentity
}

type labelsKey string

func labelsKeyFromLabelArray(lbls labels.LabelArray) labelsKey {
	return labelsKey(lbls.String())
}

func newIdentityStore() *identityStore {
	return &identityStore{
		byID:     make(map[identity.NumericIdentity]labels.LabelArray),
		byLabels: make(map[labelsKey]identity.NumericIdentity),
	}
}

func (s *identityStore) upsert(id identity.NumericIdentity, lbls labels.LabelArray) {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldLbls, ok := s.byID[id]
	if ok {
		// when upserting an entry for an existing identity, make sure to remove the old
		// labels -> identity mapping.
		delete(s.byLabels, labelsKeyFromLabelArray(oldLbls))
	}

	s.byID[id] = lbls
	s.byLabels[labelsKeyFromLabelArray(lbls)] = id
}

func (s *identityStore) remove(id identity.NumericIdentity) {
	s.mu.Lock()
	defer s.mu.Unlock()

	lbls, ok := s.byID[id]
	if !ok {
		return
	}

	delete(s.byID, id)
	delete(s.byLabels, labelsKeyFromLabelArray(lbls))
}

func (s *identityStore) find(lbls labels.LabelArray) (id identity.NumericIdentity, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := labelsKeyFromLabelArray(lbls)
	id, ok = s.byLabels[key]
	return
}

func extractLabels(in []*pb.Label) labels.LabelArray {
	lbls := make(labels.LabelArray, 0, len(in))
	for _, l := range in {
		src := l.GetSource()
		// If an identity is constituted of labels with sources other than FQDN (such as
		// CIDR), it will never be matched by the labels from matching FQDN selectors, hence
		// the identity will never be used in offline policy mode.
		if src != labels.LabelSourceFQDN && !isWorldLabel(l) {
			return nil
		}
		lbls = append(lbls, labels.NewLabel(l.GetKey(), l.GetValue(), src))
	}
	return lbls.Sort()
}

func isWorldLabel(l *pb.Label) bool {
	if l.GetSource() != labels.LabelSourceReserved {
		return false
	}
	switch l.GetKey() {
	case labels.IDNameWorld, labels.IDNameWorldIPv4, labels.IDNameWorldIPv6:
		return l.GetValue() == ""
	}
	return false
}

func (r *remoteNameManager) updateFQDNSelector(m *pb.FQDNSelectorUpdate) {
	switch m.Type {
	case pb.UpdateType_UPDATETYPE_UPSERT:
		selector := transformSelector(m.GetSelector())
		if err := r.selectors.upsert(selector); err != nil {
			r.logger.Error("Failed to upsert FQDN selector",
				logfields.Error, err,
				logfields.Selector, selector,
			)
		}
	case pb.UpdateType_UPDATETYPE_REMOVE:
		r.selectors.remove(transformSelector(m.GetSelector()))
	case pb.UpdateType_UPDATETYPE_BOOKMARK:
		// TODO
	default:
		r.logger.Warn("Unknown FQDN selector update type", logfields.Type, m.Type)
	}
}

type selectorStore struct {
	mu lock.RWMutex

	selectors map[api.FQDNSelector]*regexp.Regexp
}

func newSelectorStore(logger *slog.Logger, cfg Config) *selectorStore {
	// TODO: drop this and the logger and cfg params once https://github.com/cilium/cilium/pull/40365 landed in main-ce
	re.InitRegexCompileLRU(logger, int(cfg.FQDNRegexCompileLRUSize))

	return &selectorStore{
		selectors: make(map[api.FQDNSelector]*regexp.Regexp),
	}
}

func (s *selectorStore) upsert(selector api.FQDNSelector) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	re, err := selector.ToRegex()
	if err != nil {
		return err
	}
	s.selectors[selector] = re
	return nil
}

func (s *selectorStore) remove(selector api.FQDNSelector) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.selectors, selector)
}

func (s *selectorStore) match(name string) []api.FQDNSelector {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var selectors []api.FQDNSelector
	for selector, re := range s.selectors {
		if re.MatchString(name) {
			selectors = append(selectors, selector)
		}
	}
	return selectors
}

func transformSelector(m *pb.FQDNSelector) api.FQDNSelector {
	return api.FQDNSelector{
		MatchName:    m.GetMatchName(),
		MatchPattern: m.GetMatchPattern(),
	}
}
