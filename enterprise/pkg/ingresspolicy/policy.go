// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Isovalent

package ingresspolicy

import (
	"log/slog"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	proxyEndpoint "github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	_ proxyEndpoint.EndpointUpdater    = (*IngressPolicy)(nil)
	_ proxyEndpoint.EndpointInfoSource = (*IngressPolicy)(nil)
)

// IngressPolicy is similar to Endpoint, but without associated Endpoint
type IngressPolicy struct {
	mutex lock.RWMutex

	logger *slog.Logger

	id   identity.NumericIdentity
	name string

	rev   uint64
	owner *ingressPolicyOwner

	// proxyPolicyRevision is the policy revision that has been applied to
	// the proxy.
	proxyPolicyRevision uint64

	selectorPolicy policy.SelectorPolicy

	desiredPolicy *policy.EndpointPolicy

	// proxyStatisticsMutex is the mutex that must be held to read or write
	// proxyStatistics.
	// No other locks may be taken while holding proxyStatisticsMutex.
	proxyStatisticsMutex lock.RWMutex

	// proxyStatistics contains statistics of proxy redirects.
	// The keys in this map are policy.ProxyIDs.
	// You must hold Endpoint.proxyStatisticsMutex to read or write it.
	proxyStatistics map[string]*models.ProxyStatistics
}

// NewIngressPolicy returns a new instance of Ingress Policy
func NewIngressPolicy(logger *slog.Logger, id identity.NumericIdentity, name string, selectorPolicy policy.SelectorPolicy, rev uint64) *IngressPolicy {
	owner := &ingressPolicyOwner{
		logger: logger,
		name:   name,
		id:     uint64(id.Uint32()),
	}

	res := &IngressPolicy{
		logger:          logger,
		id:              id,
		rev:             rev,
		name:            name,
		owner:           owner,
		proxyStatistics: make(map[string]*models.ProxyStatistics),
		selectorPolicy:  selectorPolicy,
		desiredPolicy:   selectorPolicy.DistillPolicy(logger, owner, nil),
	}

	return res
}

// UpdateSelectorPolicy updates the selector policy for this Ingress Policy.
// It returns true if the selector policy was changed, otherwise false.
func (i *IngressPolicy) UpdateSelectorPolicy(sp policy.SelectorPolicy, rev uint64) bool {
	if sp == nil {
		return false
	}
	if i.selectorPolicy == sp {
		closer, changes := i.desiredPolicy.ConsumeMapChanges()
		defer closer()
		return !changes.Empty()
	}
	i.selectorPolicy = sp
	i.rev = rev

	// Update the desired policy with the new selector policy.
	//
	// As the selector policy is not shared with other Ingress Policy, Detach() function
	// call is optional.
	// The reason for this is that the selector policy is not shared with other is
	// due to unique security labels e.g. ingress:name=<name>.
	i.desiredPolicy = sp.DistillPolicy(i.logger, i.owner, nil)
	return true
}

// GetDesiredPolicy returns the desired Endpoint Policy for this Ingress Policy
func (i *IngressPolicy) GetDesiredPolicy() *policy.EndpointPolicy {
	return i.desiredPolicy
}

// GetPolicyNames is to satisfy the EndpointInfoSource interface.
func (i *IngressPolicy) GetPolicyNames() []string {
	return []string{i.name}
}

// GetID is to satisfy the EndpointInfoSource interface.
func (i *IngressPolicy) GetID() uint64 {
	return uint64(i.id.Uint32())
}

// GetIPv4Address is to satisfy the EndpointInfoSource interface.
func (i *IngressPolicy) GetIPv4Address() string {
	return ""
}

// GetIPv6Address is to satisfy the EndpointInfoSource interface.
func (i *IngressPolicy) GetIPv6Address() string {
	return ""
}

// ConntrackNameLocked is to satisfy the EndpointInfoSource interface.
func (i *IngressPolicy) ConntrackNameLocked() string {
	return "global"
}

// GetNamedPort is to satisfy the EndpointInfoSource interface.
func (i *IngressPolicy) GetNamedPort(ingress bool, name string, proto u8proto.U8proto) uint16 {
	return 0
}

// OnProxyPolicyUpdate is to satisfy the EndpointUpdater interface.
func (i *IngressPolicy) OnProxyPolicyUpdate(policyRevision uint64) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	if policyRevision > i.proxyPolicyRevision {
		i.proxyPolicyRevision = policyRevision
	}
}

// UpdateProxyStatistics is to satisfy the EndpointUpdater interface.
func (i *IngressPolicy) UpdateProxyStatistics(proxyType, l4Protocol string, port, proxyPort uint16, ingress, request bool, verdict accesslog.FlowVerdict) {
	key := policy.ProxyStatsKey(ingress, l4Protocol, port, proxyPort)

	i.proxyStatisticsMutex.Lock()
	defer i.proxyStatisticsMutex.Unlock()

	proxyStats, ok := i.proxyStatistics[key]
	if !ok {
		var location string
		if ingress {
			location = models.ProxyStatisticsLocationIngress
		} else {
			location = models.ProxyStatisticsLocationEgress
		}
		proxyStats = &models.ProxyStatistics{
			Location: location,
			Port:     int64(port),
			Protocol: l4Protocol,
			Statistics: &models.RequestResponseStatistics{
				Requests:  &models.MessageForwardingStatistics{},
				Responses: &models.MessageForwardingStatistics{},
			},
		}

		i.proxyStatistics[key] = proxyStats
	}

	var stats *models.MessageForwardingStatistics
	if request {
		stats = proxyStats.Statistics.Requests
	} else {
		stats = proxyStats.Statistics.Responses
	}

	stats.Received++
	metrics.ProxyPolicyL7Total.WithLabelValues("received", proxyType).Inc()

	switch verdict {
	case accesslog.VerdictForwarded:
		stats.Forwarded++
		metrics.ProxyPolicyL7Total.WithLabelValues("forwarded", proxyType).Inc()
	case accesslog.VerdictDenied:
		stats.Denied++
		metrics.ProxyPolicyL7Total.WithLabelValues("denied", proxyType).Inc()
	case accesslog.VerdictError:
		stats.Error++
		metrics.ProxyPolicyL7Total.WithLabelValues("parse_errors", proxyType).Inc()
	}
}

// GetPolicyVersionHandle is to satisfy the EndpointUpdater interface.
func (i *IngressPolicy) GetPolicyVersionHandle() *versioned.VersionHandle {
	if i.desiredPolicy != nil {
		return i.desiredPolicy.VersionHandle
	}
	return nil
}

func (i *IngressPolicy) GetRev() uint64 {
	return i.rev
}

var _ policy.PolicyOwner = (*ingressPolicyOwner)(nil)

type ingressPolicyOwner struct {
	logger *slog.Logger

	name string
	id   uint64
}

// GetID is to satisfy the PolicyOwner interface.
func (owner *ingressPolicyOwner) GetID() uint64 {
	return owner.id
}

// GetNamedPort is to satisfy the PolicyOwner interface.
func (owner *ingressPolicyOwner) GetNamedPort(ingress bool, name string, proto u8proto.U8proto) uint16 {
	return 0
}

// PolicyDebug is to satisfy the PolicyOwner interface.
func (owner *ingressPolicyOwner) PolicyDebug(fields logrus.Fields, msg string) {
	owner.logger.Debug("Ingress Policy: "+msg, logfields.Debug, fields)
}

// IsHost is to satisfy the PolicyOwner interface.
func (owner *ingressPolicyOwner) IsHost() bool {
	return false
}

// MapStateSize is to satisfy the PolicyOwner interface.
func (owner *ingressPolicyOwner) MapStateSize() int {
	return 0
}

// RegenerateIfAlive is to satisfy the PolicyOwner interface.
// This is a no-op for IngressPolicy.
func (owner *ingressPolicyOwner) RegenerateIfAlive(regenMetadata *regeneration.ExternalRegenerationMetadata) <-chan bool {
	ch := make(chan bool)
	close(ch)
	return ch
}

var _ policy.GetPolicyStatistics = (*IngressPolicyStats)(nil)

type IngressPolicyStats struct {
	waitingForPolicyRepository spanstat.SpanStat
	selectorPolicyCalculation  spanstat.SpanStat
}

func NewIngressPolicyStats() *IngressPolicyStats {
	return &IngressPolicyStats{
		waitingForPolicyRepository: spanstat.SpanStat{},
		selectorPolicyCalculation:  spanstat.SpanStat{},
	}
}

// WaitingForPolicyRepository is to satisfy the GetPolicyStatistics interface.
func (d *IngressPolicyStats) WaitingForPolicyRepository() *spanstat.SpanStat {
	return &d.waitingForPolicyRepository
}

// SelectorPolicyCalculation is to satisfy the GetPolicyStatistics interface.
func (d *IngressPolicyStats) SelectorPolicyCalculation() *spanstat.SpanStat {
	return &d.selectorPolicyCalculation
}
