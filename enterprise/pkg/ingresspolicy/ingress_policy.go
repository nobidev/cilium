// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Isovalent

package ingresspolicy

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/ciliumenvoyconfig/types"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"
)

const (
	subsystem = "ingress-policy"
)

const (
	// LabelSourceIngress is the source of the ingress policy labels.
	// This is to avoid any potential conflict with k8s labels, which can be manipulated by users.
	LabelSourceIngress = "ingress"

	// LabelNameIngress is the name of the ingress policy labels.
	LabelNameIngress = "name"
)

// ingressPolicyManager is responsible for managing the Ingress Policy for CiliumEnvoyConfig
type ingressPolicyManager struct {
	mutex lock.RWMutex

	logger *slog.Logger

	// cacheIdentityAllocator is used to look up the identity for the Ingress Policy
	cacheIdentityAllocator cache.IdentityAllocator

	// policyRepository is used to get/create the selector policy for the Ingress Policy
	policyRepository policy.PolicyRepository

	// xdsServer is used to send the distilled policy to the xDS server
	xdsServer envoy.XDSServer

	// ingressIdentities is the cache to store the identity for the Ingress Policy
	ingressIdentities map[resource.Key]*identity.Identity
	// ingressPolicies is the cache to store the Ingress Policy
	ingressPolicies map[resource.Key]*IngressPolicy
}

type ingressPolicyParam struct {
	cell.In

	Logger   *slog.Logger
	JobGroup job.Group

	Config types.CECPolicyConfig

	CacheIdentityAllocator cache.IdentityAllocator
	EndpointPolicyManager  endpointmanager.PolicyUpdateCallbackManager
	PolicyRepository       policy.PolicyRepository
	XdsServer              envoy.XDSServer
}

type Updater interface {
	EnsureIngressPolicy(ctx context.Context, key resource.Key, resourceLabels map[string]string) error
	DeleteIngressPolicy(ctx context.Context, key resource.Key, resourceLabels map[string]string) error
}

func newIngressPolicyManager(params ingressPolicyParam) Updater {
	p := &ingressPolicyManager{
		logger:                 params.Logger,
		cacheIdentityAllocator: params.CacheIdentityAllocator,
		policyRepository:       params.PolicyRepository,
		xdsServer:              params.XdsServer,
		ingressIdentities:      make(map[resource.Key]*identity.Identity),
		ingressPolicies:        make(map[resource.Key]*IngressPolicy),
	}

	// Register the policy update callback with the endpoint manager
	params.EndpointPolicyManager.RegisterPolicyUpdateCallback(subsystem, p.policyUpdateCallback)

	return p
}

// EnsureIngressPolicy will create or use existing selector policy for a respective Identity, and then send the
// distilled policy to the xDS server.
func (m *ingressPolicyManager) EnsureIngressPolicy(ctx context.Context, key resource.Key, resourceLabels map[string]string) error {
	return nil
}

// DeleteIngressPolicy will remove the network policy from the xDS server.
// Additionally, the identity and policy will be removed from the cache.
func (m *ingressPolicyManager) DeleteIngressPolicy(ctx context.Context, key resource.Key, resourceLabels map[string]string) error {
	return nil
}

// policyUpdateCallback is called from endpoint manager to perform incremental
// and full regeneration for all managed ingress policies.
func (m *ingressPolicyManager) policyUpdateCallback(idsRegen *set.Set[identity.NumericIdentity], incremental bool) error {
	return nil
}
