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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	enterpriseannotation "github.com/cilium/cilium/enterprise/pkg/annotation"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	ossreconcilerv2 "github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	bgptypes "github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ciliumslices "github.com/cilium/cilium/pkg/slices"
)

const (
	// svcHealthAdvertiseThresholdDefault defines the default threshold in minimal number of healthy backends,
	// when service routes will be advertised by the BGP Control Plane.
	svcHealthAdvertiseThresholdDefault = 1

	// gracefulShutdownCommunityValue is the community value of the GRACEFUL_SHUTDOWN BGP community
	gracefulShutdownCommunityValue = "65535:0"
)

// ServiceReconciler is an enterprise version of the OSS ServiceReconciler,
// which extends its functionality with enterprise-only features.
// If enabled, the enterprise reconciler is called upon each Reconcile() instead of the OSS reconciler
// (thanks to the same reconciler name and higher priority).
// The Enterprise reconciler calls the OSS reconciler's methods on various places to avoid code duplication.
type ServiceReconciler struct {
	mutex  lock.Mutex
	logger *slog.Logger

	jobs         job.Group
	cfg          Config
	signaler     *signaler.BGPCPSignaler
	upgrader     paramUpgrader
	peerAdvert   *IsovalentAdvertisement
	svcDiffStore store.DiffStore[*slim_corev1.Service]
	epDiffStore  store.DiffStore[*k8s.Endpoints]
	metadata     map[string]ServiceReconcilerMetadata

	// service health-checker
	db        *statedb.DB
	frontends statedb.Table[*loadbalancer.Frontend]

	// internal service health state
	svcHealth        map[loadbalancer.ServiceName]svcFrontendHealthMap // local cache of service health metadata
	svcHealthChanged map[string]map[loadbalancer.ServiceName]struct{}  // instance-specific tracker of services with modified health since last reconciliation

	// node status tracking
	nodeStatusProvider NodeStatusProvider
	nodeStatus         NodeStatus
}

type ServiceReconcilerOut struct {
	cell.Out

	Reconciler ossreconcilerv2.ConfigReconciler `group:"bgp-config-reconciler-v2"`
}

type ServiceReconcilerIn struct {
	cell.In
	Lifecycle cell.Lifecycle

	JobGroup     job.Group
	DB           *statedb.DB
	Frontends    statedb.Table[*loadbalancer.Frontend]
	Cfg          Config
	BGPConfig    config.Config
	Logger       *slog.Logger
	Signaler     *signaler.BGPCPSignaler
	Upgrader     paramUpgrader
	PeerAdvert   *IsovalentAdvertisement
	SvcDiffStore store.DiffStore[*slim_corev1.Service]
	EPDiffStore  store.DiffStore[*k8s.Endpoints]
	NSProvider   NodeStatusProvider
}

// svcFrontendHealth keeps health information about a service frontend, as received from the service health-checker
type svcFrontendHealth struct {
	frontendAddr        loadbalancer.L3n4Addr // frontend address (one service can have multiple frontend addresses)
	activeBackendsCount int
}

// svcFrontendHealthMap is a map of service frontend health information keyed by the frontend address
type svcFrontendHealthMap map[loadbalancer.L3n4Addr]*svcFrontendHealth

// ServiceReconcilerMetadata holds any announced service CIDRs per address family.
type ServiceReconcilerMetadata struct {
	ServicePaths          ossreconcilerv2.ResourceAFPathsMap
	ServiceRoutePolicies  ossreconcilerv2.ResourceRoutePolicyMap
	ServiceAdvertisements PeerAdvertisements
}

func NewServiceReconciler(in ServiceReconcilerIn) ServiceReconcilerOut {
	if !in.BGPConfig.Enabled || in.SvcDiffStore == nil || in.EPDiffStore == nil {
		return ServiceReconcilerOut{}
	}

	r := &ServiceReconciler{
		logger:             in.Logger.With(bgptypes.ReconcilerLogField, "Service"),
		cfg:                in.Cfg,
		signaler:           in.Signaler,
		db:                 in.DB,
		frontends:          in.Frontends,
		jobs:               in.JobGroup,
		upgrader:           in.Upgrader,
		nodeStatusProvider: in.NSProvider,
		peerAdvert:         in.PeerAdvert,
		svcDiffStore:       in.SvcDiffStore,
		epDiffStore:        in.EPDiffStore,
		metadata:           make(map[string]ServiceReconcilerMetadata),
		svcHealth:          make(map[loadbalancer.ServiceName]svcFrontendHealthMap),
		svcHealthChanged:   make(map[string]map[loadbalancer.ServiceName]struct{}),
	}

	// start observing frontends for backend health changes.
	if r.cfg.SvcHealthCheckingEnabled && r.jobs != nil {
		r.jobs.Add(job.Observer[statedb.Change[*loadbalancer.Frontend]](
			"service-health",
			r.frontendChanged,
			statedb.Observable[*loadbalancer.Frontend](r.db, r.frontends)))
	}

	return ServiceReconcilerOut{
		Reconciler: r,
	}
}

func (r *ServiceReconciler) Name() string {
	return ServiceReconcilerName
}

func (r *ServiceReconciler) Priority() int {
	return ServiceReconcilerPriority
}

// Init is called when a new BGP instance is being initialized.
func (r *ServiceReconciler) Init(i *instance.BGPInstance) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if i == nil {
		return fmt.Errorf("BUG: service reconciler initialization with nil BGPInstance")
	}
	// initialize service health tracker map for this instance
	r.svcHealthChanged[i.Name] = make(map[loadbalancer.ServiceName]struct{})

	r.svcDiffStore.InitDiff(r.diffID(i.Name))
	r.epDiffStore.InitDiff(r.diffID(i.Name))

	r.metadata[i.Name] = ServiceReconcilerMetadata{
		ServicePaths:          make(ossreconcilerv2.ResourceAFPathsMap),
		ServiceRoutePolicies:  make(ossreconcilerv2.ResourceRoutePolicyMap),
		ServiceAdvertisements: make(PeerAdvertisements),
	}
	return nil
}

// Cleanup is called when a new BGP instance is being removed.
func (r *ServiceReconciler) Cleanup(i *instance.BGPInstance) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if i != nil {
		// cleanup service health tracker map for this instance
		delete(r.svcHealthChanged, i.Name)

		r.svcDiffStore.CleanupDiff(r.diffID(i.Name))
		r.epDiffStore.CleanupDiff(r.diffID(i.Name))

		delete(r.metadata, i.Name)
	}
}

func (r *ServiceReconciler) getMetadata(i *EnterpriseBGPInstance) ServiceReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *ServiceReconciler) setMetadata(i *EnterpriseBGPInstance, metadata ServiceReconcilerMetadata) {
	r.metadata[i.Name] = metadata
}

// ServiceHealthUpdate is called by the service health-checker upon changes in service health based on backend health-checking.
func (r *ServiceReconciler) frontendChanged(ctx context.Context, change statedb.Change[*loadbalancer.Frontend]) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	fe := change.Object

	if fe.Type != loadbalancer.SVCTypeLoadBalancer || fe.ServiceName.Name() == "" {
		return nil // ignore updates for non-LB svcFrontendsHealth and unknown services
	}
	if fe.Address.Scope() != loadbalancer.ScopeExternal {
		// We are only interested in updates with external address lookup scope.
		// In case of ExternalTraficPolicy == local, these contain only local endpoints, otherwise they contain all endpoints.
		return nil
	}

	svcFrontendsHealth, found := r.svcHealth[fe.ServiceName]
	if change.Deleted {
		r.logger.Debug("Service health update: frontend deleted",
			types.ServiceIDLogField, fe.ServiceName,
			types.ServiceAddressLogField, fe.Address,
		)
		if found {
			// Due to the service node selector annotation we cannot just delete the frontend health,
			// but rather just need to give it zero backends.
			if frontendHealth := svcFrontendsHealth[fe.Address]; frontendHealth != nil {
				frontendHealth.activeBackendsCount = 0
			}
		}
	} else {
		if !found {
			svcFrontendsHealth = make(svcFrontendHealthMap)
			r.svcHealth[fe.ServiceName] = svcFrontendsHealth
		}

		backendsCount := 0
		for be := range fe.Backends {
			if !be.Unhealthy && be.State == loadbalancer.BackendStateActive {
				backendsCount++
			}
		}

		r.logger.Debug("Service health update",
			types.ServiceIDLogField, fe.ServiceName,
			types.ServiceAddressLogField, fe.Address,
			types.BackendCountLogField, backendsCount,
		)

		frontendHealth := svcFrontendsHealth[fe.Address]
		if frontendHealth == nil {
			frontendHealth = &svcFrontendHealth{
				frontendAddr: fe.Address,
			}
			svcFrontendsHealth[fe.Address] = frontendHealth
		}

		// update cache of active backends
		frontendHealth.activeBackendsCount = backendsCount
	}

	// mark the service for reconciliation
	for _, instanceMap := range r.svcHealthChanged {
		instanceMap[fe.ServiceName] = struct{}{}
	}

	// trigger a reconciliation
	r.signaler.Event(struct{}{})
	return nil
}

// Reconcile mirrors the OSS reconciler's Reconcile() code path but calls enterprise-specific reconcileServices().
func (r *ServiceReconciler) Reconcile(ctx context.Context, p ossreconcilerv2.ReconcileParams) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	iParams, err := r.upgrader.upgrade(p)
	if err != nil {
		if errors.Is(err, ErrEntNodeConfigNotFound) {
			r.logger.Debug("Enterprise node config not found yet, skipping reconciliation")
			return nil
		}
		return err
	}

	r.logger.Debug("Performing CEE Service reconciliation")

	desiredPeerAdverts, err := r.peerAdvert.GetConfiguredPeerAdvertisements(iParams.DesiredConfig, v1.BGPServiceAdvert)
	if err != nil {
		return err
	}

	ls, err := r.populateLocalServices(p.CiliumNode.Name)
	if err != nil {
		return fmt.Errorf("failed to populate local services: %w", err)
	}

	// must be done before reconciling paths and policies since it sets metadata with latest desiredPeerAdverts
	reqFullReconcile := r.modifiedServiceAdvertisements(iParams, desiredPeerAdverts)

	if r.cfg.MaintenanceGracefulShutdownEnabled || r.cfg.MaintenanceWithdrawTime > 0 {
		// if node status changed, perform full reconcile
		nodeStatus := r.nodeStatusProvider.GetNodeStatus()
		if nodeStatus != r.nodeStatus {
			r.nodeStatus = nodeStatus
			reqFullReconcile = true
		}
	}

	err = r.reconcileServices(ctx, iParams, desiredPeerAdverts, ls, reqFullReconcile)

	if err == nil && reqFullReconcile {
		// update svc advertisements in metadata only if the reconciliation was successful
		r.updateServiceAdvertisementsMetadata(iParams, desiredPeerAdverts)
	}
	return err
}

// Populate locally available services used for externalTrafficPolicy=local handling
func (r *ServiceReconciler) populateLocalServices(localNodeName string) (sets.Set[resource.Key], error) {
	ls := sets.New[resource.Key]()

	epList, err := r.epDiffStore.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list EPs from diffstore: %w", err)
	}

endpointsLoop:
	for _, eps := range epList {
		_, exists, err := r.resolveSvcFromEndpoints(eps)
		if err != nil {
			// Cannot resolve service from EPs. We have nothing to do here.
			continue
		}

		if !exists {
			// No service associated with this endpoint. We're not interested in this.
			continue
		}

		svcKey := resource.Key{
			Name:      eps.ServiceName.Name(),
			Namespace: eps.ServiceName.Namespace(),
		}

		for _, be := range eps.Backends {
			if !be.Conditions.IsTerminating() && be.NodeName == localNodeName {
				// At least one endpoint is available on this node. We
				// can add service to the local services set.
				ls.Insert(svcKey)
				continue endpointsLoop
			}
		}
	}

	return ls, nil
}

// reconcileServices mirrors the OSS reconciler's reconcileServices() code path and applies enterprise-specific
// service reconciliation logic on top of it.
func (r *ServiceReconciler) reconcileServices(ctx context.Context, p EnterpriseReconcileParams,
	desiredPeerAdverts PeerAdvertisements, ls sets.Set[resource.Key], fullReconcile bool) error {
	var (
		toReconcile []*slim_corev1.Service
		toWithdraw  []resource.Key

		desiredSvcRoutePolicies ossreconcilerv2.ResourceRoutePolicyMap
		desiredSvcPaths         ossreconcilerv2.ResourceAFPathsMap

		err error
	)

	if fullReconcile {
		r.logger.Debug("Performing all services reconciliation")

		// get all services to reconcile and to withdraw.
		toReconcile, toWithdraw, err = r.fullReconciliationServiceList(p)
		if err != nil {
			return err
		}
	} else {
		r.logger.Debug("Performing modified services reconciliation")

		// get modified services to reconcile and to withdraw.
		// Note: we should call svc diff only once in a reconcile loop.
		toReconcile, toWithdraw, err = r.diffReconciliationServiceList(p)
		if err != nil {
			return err
		}
	}
	r.logger.Debug("Reconciling services",
		types.ToReconcileLogField, len(toReconcile),
		types.ToWithdrawLogField, len(toWithdraw),
	)

	// get desired service route policies
	desiredSvcRoutePolicies, err = r.getDesiredRoutePolicies(desiredPeerAdverts, toReconcile, toWithdraw, ls)
	if err != nil {
		return err
	}

	// reconcile service route policies
	err = r.reconcileSvcRoutePolicies(ctx, p, desiredSvcRoutePolicies)
	if err != nil {
		return fmt.Errorf("failed to reconcile service route policies: %w", err)
	}

	if r.cfg.SvcHealthCheckingEnabled && !fullReconcile {
		// in case of diff reconciliation, also reconcile services with modified health state
		// NOTE: do not adapt toReconcile before reconciling route policies - removing/adding route policy would cause session reset
		toReconcile = append(toReconcile, r.healthModifiedServices(p)...)

		// we may now have duplicated services in toReconcile, deduplicate
		toReconcile = ciliumslices.Unique(toReconcile)
	}

	// get desired service paths
	desiredSvcPaths, err = r.getDesiredPaths(desiredPeerAdverts, toReconcile, toWithdraw, ls)
	if err != nil {
		return err
	}

	// reconcile service paths
	err = r.reconcilePaths(ctx, p, desiredSvcPaths)
	if err != nil {
		return fmt.Errorf("failed to reconcile service paths: %w", err)
	}

	if r.cfg.SvcHealthCheckingEnabled {
		// delete the svc from the service-specific health caches
		for _, key := range toWithdraw {
			svcID := loadbalancer.NewServiceName(key.Namespace, key.Name)
			delete(r.svcHealth, svcID)
			delete(r.svcHealthChanged[p.BGPInstance.Name], svcID)
		}
	}

	return nil
}

func (r *ServiceReconciler) reconcilePaths(ctx context.Context, p EnterpriseReconcileParams, desiredSvcPaths ossreconcilerv2.ResourceAFPathsMap) error {
	var err error
	metadata := r.getMetadata(p.BGPInstance)

	metadata.ServicePaths, err = ossreconcilerv2.ReconcileResourceAFPaths(ossreconcilerv2.ReconcileResourceAFPathsParams{
		Logger:                 r.logger.With(bgptypes.InstanceLogField, p.DesiredConfig.Name),
		Ctx:                    ctx,
		Router:                 p.BGPInstance.Router,
		DesiredResourceAFPaths: desiredSvcPaths,
		CurrentResourceAFPaths: metadata.ServicePaths,
	})

	r.setMetadata(p.BGPInstance, metadata)
	return err
}

// healthModifiedServices returns a list of services with modified health state since the last call of this method.
func (r *ServiceReconciler) healthModifiedServices(p EnterpriseReconcileParams) []*slim_corev1.Service {
	var modified []*slim_corev1.Service

	// Deleting keys doesn't shrink the memory size, so we shrink it by recreating the map
	// if it reaches above the threshold (arbitrary value).
	// Below the threshold we don't recreate the map to avoid unnecessary allocation.
	const shrinkThreshold = 64
	shrink := len(r.svcHealthChanged) > shrinkThreshold

	// loop over services with modified health since last reconciliation
	for svcID := range r.svcHealthChanged[p.BGPInstance.Name] {
		svc, exists, err := r.getSvcByID(svcID)
		if err != nil {
			r.logger.Warn("Could not retrieve service, skipping its reconciliation",
				types.ServiceIDLogField, svcID,
				logfields.Error, err)
			continue
		}
		if !exists {
			continue // svc not found (may have been deleted already), nothing to do
		}
		modified = append(modified, svc)
		if !shrink {
			delete(r.svcHealthChanged[p.BGPInstance.Name], svcID)
		}
	}

	if shrink {
		// re-create the health tracking map
		r.svcHealthChanged[p.BGPInstance.Name] = make(map[loadbalancer.ServiceName]struct{})
	}
	return modified
}

// getDesiredPaths mirrors the OSS reconciler's getDesiredPaths() method, but calls the enterprise
// version of getServiceAFPaths().
func (r *ServiceReconciler) getDesiredPaths(desiredPeerAdverts PeerAdvertisements, toReconcile []*slim_corev1.Service, toWithdraw []resource.Key, ls sets.Set[resource.Key]) (ossreconcilerv2.ResourceAFPathsMap, error) {

	desiredServiceAFPaths := make(ossreconcilerv2.ResourceAFPathsMap)
	for _, svc := range toReconcile {
		svcKey := resource.Key{
			Name:      svc.GetName(),
			Namespace: svc.GetNamespace(),
		}

		afPaths, err := r.getServiceAFPaths(desiredPeerAdverts, svc, ls)
		if err != nil {
			return nil, err
		}
		desiredServiceAFPaths[svcKey] = afPaths
	}

	for _, svcKey := range toWithdraw {
		// for withdrawn services, we need to set paths to nil.
		desiredServiceAFPaths[svcKey] = nil
	}

	return desiredServiceAFPaths, nil
}

// getServiceAFPaths applies enterprise-specific filtering for paths that should be advertised for a service.
func (r *ServiceReconciler) getServiceAFPaths(desiredPeerAdverts PeerAdvertisements,
	svc *slim_corev1.Service, ls sets.Set[resource.Key]) (ossreconcilerv2.AFPathsMap, error) {

	// do not advertise the service if node in maintenance mode with withdraw timeout expired
	if r.nodeStatus == NodeMaintenanceTimeExpired {
		return nil, nil
	}

	// the service with no-advertisement annotation should not be announced
	if r.svcHasNoAdvertisementAnnotations(svc) {
		return nil, nil
	}

	// retrieve all service paths to advertise from the OSS reconciler
	desiredFamilyAdverts, err := r.getAllServiceAFPaths(desiredPeerAdverts, svc, ls)
	if err != nil {
		return nil, err
	}

	// ignore service frontends with no healthy backends
	if r.cfg.SvcHealthCheckingEnabled {
		for _, pathMap := range desiredFamilyAdverts {
			for path := range pathMap {
				prefix, err := netip.ParsePrefix(path)
				if err != nil {
					return nil, fmt.Errorf("invalid service advertisement path %s: %w", path, err)
				}
				if !r.svcFrontendHealthy(svc, prefix.Addr()) {
					// delete the route to frontend with non-healthy backends from desired advertisements
					delete(pathMap, path)
				}
			}
		}
	}

	return desiredFamilyAdverts, nil
}

func (r *ServiceReconciler) getAllServiceAFPaths(desiredPeerAdverts PeerAdvertisements, svc *slim_corev1.Service, ls sets.Set[resource.Key]) (ossreconcilerv2.AFPathsMap, error) {
	desiredFamilyAdverts := make(ossreconcilerv2.AFPathsMap)

	for _, peerFamilyAdverts := range desiredPeerAdverts {
		for family, familyAdverts := range peerFamilyAdverts {
			agentFamily := bgptypes.ToAgentFamily(family)

			for _, advert := range familyAdverts {
				// get prefixes for the service
				desiredPrefixes, err := r.getServicePrefixes(svc, advert, ls)
				if err != nil {
					return nil, err
				}

				for _, prefix := range desiredPrefixes {
					path := bgptypes.NewPathForPrefix(prefix)
					path.Family = agentFamily

					// we only add path corresponding to the family of the prefix.
					if agentFamily.Afi == bgptypes.AfiIPv4 && prefix.Addr().Is4() {
						ossreconcilerv2.AddPathToAFPathsMap(desiredFamilyAdverts, agentFamily, path, path.NLRI.String())
					}
					if agentFamily.Afi == bgptypes.AfiIPv6 && prefix.Addr().Is6() {
						ossreconcilerv2.AddPathToAFPathsMap(desiredFamilyAdverts, agentFamily, path, path.NLRI.String())
					}
				}
			}
		}
	}
	return desiredFamilyAdverts, nil
}

func (r *ServiceReconciler) getServicePrefixes(svc *slim_corev1.Service, advert v1.BGPAdvertisement, ls sets.Set[resource.Key]) ([]netip.Prefix, error) {
	if advert.AdvertisementType != v1.BGPServiceAdvert {
		return nil, fmt.Errorf("unexpected advertisement type: %s", advert.AdvertisementType)
	}

	if advert.Selector == nil || advert.Service == nil {
		// advertisement has no selector or no service options, default behavior is not to match any service.
		return nil, nil
	}

	// The vRouter has a service selector, so determine the desired routes.
	svcSelector, err := slim_metav1.LabelSelectorAsSelector(advert.Selector)
	if err != nil {
		return nil, fmt.Errorf("labelSelectorAsSelector: %w", err)
	}

	// Ignore non matching services.
	if !svcSelector.Matches(serviceLabelSet(svc)) {
		return nil, nil
	}

	var desiredRoutes []netip.Prefix
	// Loop over the service upsertAdverts and determine the desired routes.
	for _, svcAdv := range advert.Service.Addresses {
		switch svcAdv {
		case v2.BGPLoadBalancerIPAddr:
			desiredRoutes = append(desiredRoutes, r.getLBSvcPaths(svc, ls, advert)...)
		case v2.BGPClusterIPAddr:
			desiredRoutes = append(desiredRoutes, r.getClusterIPPaths(svc, ls, advert)...)
		case v2.BGPExternalIPAddr:
			desiredRoutes = append(desiredRoutes, r.getExternalIPPaths(svc, ls, advert)...)
		}
	}

	return desiredRoutes, nil
}

func (r *ServiceReconciler) getExternalIPPaths(svc *slim_corev1.Service, ls sets.Set[resource.Key], advert v1.BGPAdvertisement) []netip.Prefix {
	var desiredRoutes []netip.Prefix
	// Ignore externalTrafficPolicy == Local && no local EPs.
	if svc.Spec.ExternalTrafficPolicy == slim_corev1.ServiceExternalTrafficPolicyLocal &&
		!hasLocalEndpoints(svc, ls) {
		return desiredRoutes
	}
	for _, extIP := range svc.Spec.ExternalIPs {
		if extIP == "" {
			continue
		}
		addr, err := netip.ParseAddr(extIP)
		if err != nil {
			continue
		}
		prefix, err := addr.Prefix(r.getPrefixLength(svc, addr, advert, v2.BGPExternalIPAddr))
		if err != nil {
			continue
		}
		desiredRoutes = append(desiredRoutes, prefix)
	}
	return desiredRoutes
}

func (r *ServiceReconciler) getClusterIPPaths(svc *slim_corev1.Service, ls sets.Set[resource.Key], advert v1.BGPAdvertisement) []netip.Prefix {
	var desiredRoutes []netip.Prefix
	// Ignore internalTrafficPolicy == Local && no local EPs.
	if svc.Spec.InternalTrafficPolicy != nil && *svc.Spec.InternalTrafficPolicy == slim_corev1.ServiceInternalTrafficPolicyLocal &&
		!hasLocalEndpoints(svc, ls) {
		return desiredRoutes
	}
	if svc.Spec.ClusterIP == "" || len(svc.Spec.ClusterIPs) == 0 || svc.Spec.ClusterIP == corev1.ClusterIPNone {
		return desiredRoutes
	}
	ips := sets.New[string]()
	if svc.Spec.ClusterIP != "" {
		ips.Insert(svc.Spec.ClusterIP)
	}
	for _, clusterIP := range svc.Spec.ClusterIPs {
		if clusterIP == "" || clusterIP == corev1.ClusterIPNone {
			continue
		}
		ips.Insert(clusterIP)
	}
	for _, ip := range sets.List(ips) {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		prefix, err := addr.Prefix(r.getPrefixLength(svc, addr, advert, v2.BGPClusterIPAddr))
		if err != nil {
			continue
		}
		desiredRoutes = append(desiredRoutes, prefix)
	}
	return desiredRoutes
}

func (r *ServiceReconciler) getLBSvcPaths(svc *slim_corev1.Service, ls sets.Set[resource.Key], advert v1.BGPAdvertisement) []netip.Prefix {
	var desiredRoutes []netip.Prefix
	if svc.Spec.Type != slim_corev1.ServiceTypeLoadBalancer {
		return desiredRoutes
	}
	// Ignore externalTrafficPolicy == Local && no local EPs.
	if svc.Spec.ExternalTrafficPolicy == slim_corev1.ServiceExternalTrafficPolicyLocal &&
		!hasLocalEndpoints(svc, ls) {
		return desiredRoutes
	}
	// Ignore service managed by an unsupported LB class.
	if svc.Spec.LoadBalancerClass != nil && *svc.Spec.LoadBalancerClass != v2.BGPLoadBalancerClass {
		// The service is managed by a different LB class.
		return desiredRoutes
	}
	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		if ingress.IP == "" {
			continue
		}
		addr, err := netip.ParseAddr(ingress.IP)
		if err != nil {
			continue
		}
		prefix, err := addr.Prefix(r.getPrefixLength(svc, addr, advert, v2.BGPLoadBalancerIPAddr))
		if err != nil {
			continue
		}
		desiredRoutes = append(desiredRoutes, prefix)
	}
	return desiredRoutes
}

// svcFrontendHealthy checks whether a service frontend is considered healthy based on the cached health state.
func (r *ServiceReconciler) svcFrontendHealthy(svc *slim_corev1.Service, frontendIP netip.Addr) bool {
	// if the hc probe interval annotation is not set on the service, it means that health-checking is not enabled
	// for the service, and it is considered to be always healthy
	if _, exists := annotation.Get(svc, enterpriseannotation.ServiceHealthProbeInterval); !exists {
		return true
	}

	// retrieve service health state
	svcID := parseServiceID(svc)
	feHealth, found := r.svcHealth[svcID]
	if !found {
		// if there is no health info for the service (yet), we assume it is not healthy
		return false
	}

	// determine service's health check advertise threshold
	threshold := svcHealthAdvertiseThresholdDefault
	if annVal, ok := annotation.Get(svc, enterpriseannotation.ServiceHealthBGPAdvertiseThreshold); ok {
		if val, err := strconv.Atoi(annVal); err == nil {
			threshold = val
		}
	}

	// compile service port set
	svcPorts := sets.New[loadbalancer.L4Addr]()
	for _, svcPort := range svc.Spec.Ports {
		svcPorts.Insert(loadbalancer.NewL4Addr(svcProtocolToLBL4Type(svcPort.Protocol), uint16(svcPort.Port)))
	}

	// loop over all service frontend addresses with known health state
	for _, fe := range feHealth {
		// ignore frontends with non-matching frontend address
		// (e.g. in case of dual-stack with an IPv4 and IPv6 frontend, only consider proper address family)
		if fe.frontendAddr.Addr() != frontendIP {
			continue
		}
		// ignore frontends with non-matching L4 proto / port
		// (e.g. ignore stale frontend health after removing a service port)
		if !svcPorts.Has(loadbalancer.NewL4Addr(fe.frontendAddr.Protocol(), fe.frontendAddr.Port())) {
			continue
		}
		// if for any frontend we do not have enough backends, we declare the service as not healthy
		// (e.g. in case of two service ports: one healthy and one unhealthy, the service is considered unhealthy)
		if fe.activeBackendsCount < threshold {
			return false
		}
	}
	return true
}

// svcHasNoAdvertisementAnnotations checks whether a service has no-advertisement annotations set
func (r *ServiceReconciler) svcHasNoAdvertisementAnnotations(svc *slim_corev1.Service) bool {
	if _, exists := annotation.Get(svc, enterpriseannotation.ServiceNoAdvertisement); exists {
		return true
	}
	return false
}

// getSvcByID retrieves a service by the provided service ID.
func (r *ServiceReconciler) getSvcByID(svcID loadbalancer.ServiceName) (*slim_corev1.Service, bool, error) {
	key := resource.Key{
		Name:      svcID.Name(),
		Namespace: svcID.Namespace(),
	}
	return r.svcDiffStore.GetByKey(key)
}

// modifiedServiceAdvertisements checks whether the service advertisements in the reconciler metadata are different
// from the provided desired advertisements.
func (r *ServiceReconciler) modifiedServiceAdvertisements(iParams EnterpriseReconcileParams, desiredPeerAdverts PeerAdvertisements) bool {
	currentMetadata := r.getMetadata(iParams.BGPInstance)

	return !PeerAdvertisementsEqual(currentMetadata.ServiceAdvertisements, desiredPeerAdverts)
}

// updateServiceAdvertisementsMetadata updates the provided ServiceAdvertisements in the reconciler metadata.
func (r *ServiceReconciler) updateServiceAdvertisementsMetadata(iParams EnterpriseReconcileParams, peerAdverts PeerAdvertisements) {
	// current metadata
	serviceMetadata := r.getMetadata(iParams.BGPInstance)

	// update ServiceAdvertisements in the metadata
	r.setMetadata(iParams.BGPInstance, ServiceReconcilerMetadata{
		ServicePaths:          serviceMetadata.ServicePaths,
		ServiceRoutePolicies:  serviceMetadata.ServiceRoutePolicies,
		ServiceAdvertisements: peerAdverts,
	})
}

func (r *ServiceReconciler) fullReconciliationServiceList(p EnterpriseReconcileParams) (toReconcile []*slim_corev1.Service, toWithdraw []resource.Key, err error) {
	// re-init diff in diffstores, so that it contains only changes since the last full reconciliation.
	r.svcDiffStore.InitDiff(r.diffID(p.BGPInstance.Name))
	r.epDiffStore.InitDiff(r.diffID(p.BGPInstance.Name))

	serviceAFPaths := r.getMetadata(p.BGPInstance).ServicePaths

	// check for services which are no longer present
	for svcKey := range serviceAFPaths {
		_, exists, err := r.svcDiffStore.GetByKey(svcKey)
		if err != nil {
			return nil, nil, fmt.Errorf("svcDiffStore.GetByKey(): %w", err)
		}

		// if the service no longer exists, withdraw it
		if !exists {
			toWithdraw = append(toWithdraw, svcKey)
		}
	}

	// check all services for advertisement
	toReconcile, err = r.svcDiffStore.List()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list services from svcDiffstore: %w", err)
	}
	return
}

// diffReconciliationServiceList returns a list of services to reconcile and to withdraw when
// performing partial (diff) service reconciliation.
func (r *ServiceReconciler) diffReconciliationServiceList(p EnterpriseReconcileParams) (toReconcile []*slim_corev1.Service, toWithdraw []resource.Key, err error) {
	upserted, deleted, err := r.svcDiffStore.Diff(r.diffID(p.BGPInstance.Name))
	if err != nil {
		return nil, nil, fmt.Errorf("svc store diff: %w", err)
	}

	// For externalTrafficPolicy=local, we need to take care of
	// the endpoint changes in addition to the service changes.
	// Take a diff of the EPs and get affected services.
	// Also upsert services with deleted endpoints to handle potential withdrawal.
	epsUpserted, epsDeleted, err := r.epDiffStore.Diff(r.diffID(p.BGPInstance.Name))
	if err != nil {
		return nil, nil, fmt.Errorf("EPs store diff: %w", err)
	}

	for _, eps := range slices.Concat(epsUpserted, epsDeleted) {
		svc, exists, err := r.resolveSvcFromEndpoints(eps)
		if err != nil {
			// Cannot resolve service from EPs. We have nothing to do here.
			continue
		}

		if !exists {
			// No service associated with this endpoint. We're not interested in this.
			continue
		}

		// We only need Endpoints tracking for externalTrafficPolicy=Local or internalTrafficPolicy=Local services.
		if svc.Spec.ExternalTrafficPolicy == slim_corev1.ServiceExternalTrafficPolicyLocal ||
			(svc.Spec.InternalTrafficPolicy != nil && *svc.Spec.InternalTrafficPolicy == slim_corev1.ServiceInternalTrafficPolicyLocal) {
			upserted = append(upserted, svc)
		}
	}

	// We may have duplicated services that changes happened for both of
	// service and associated EPs.
	deduped := ciliumslices.UniqueFunc(
		upserted,
		func(i int) resource.Key {
			return resource.Key{
				Name:      upserted[i].GetName(),
				Namespace: upserted[i].GetNamespace(),
			}
		},
	)

	deletedKeys := make([]resource.Key, 0, len(deleted))
	for _, svc := range deleted {
		deletedKeys = append(deletedKeys, resource.Key{Name: svc.Name, Namespace: svc.Namespace})
	}

	return deduped, deletedKeys, nil
}

func (r *ServiceReconciler) reconcileSvcRoutePolicies(ctx context.Context, p EnterpriseReconcileParams, desiredSvcRoutePolicies ossreconcilerv2.ResourceRoutePolicyMap) error {
	var err error
	metadata := r.getMetadata(p.BGPInstance)
	for svcKey, desiredSvcRoutePolicies := range desiredSvcRoutePolicies {
		currentSvcRoutePolicies, exists := metadata.ServiceRoutePolicies[svcKey]
		if !exists && len(desiredSvcRoutePolicies) == 0 {
			continue
		}

		updatedSvcRoutePolicies, rErr := ossreconcilerv2.ReconcileRoutePolicies(&ossreconcilerv2.ReconcileRoutePoliciesParams{
			Logger:          r.logger.With(bgptypes.InstanceLogField, p.DesiredConfig.Name),
			Ctx:             ctx,
			Router:          p.BGPInstance.Router,
			DesiredPolicies: desiredSvcRoutePolicies,
			CurrentPolicies: currentSvcRoutePolicies,
		})

		if rErr == nil && len(desiredSvcRoutePolicies) == 0 {
			delete(metadata.ServiceRoutePolicies, svcKey)
		} else {
			metadata.ServiceRoutePolicies[svcKey] = updatedSvcRoutePolicies
		}
		err = errors.Join(err, rErr)
	}
	r.setMetadata(p.BGPInstance, metadata)
	return err
}

func (r *ServiceReconciler) getDesiredRoutePolicies(desiredPeerAdverts PeerAdvertisements, toUpdate []*slim_corev1.Service, toRemove []resource.Key, ls sets.Set[resource.Key]) (ossreconcilerv2.ResourceRoutePolicyMap, error) {
	desiredSvcRoutePolicies := make(ossreconcilerv2.ResourceRoutePolicyMap)

	for _, svc := range toUpdate {
		svcKey := resource.Key{
			Name:      svc.GetName(),
			Namespace: svc.GetNamespace(),
		}

		// get desired route policies for the service
		svcRoutePolicies, err := r.getDesiredSvcRoutePolicies(desiredPeerAdverts, svc, ls)
		if err != nil {
			return nil, err
		}

		desiredSvcRoutePolicies[svcKey] = svcRoutePolicies
	}

	for _, svcKey := range toRemove {
		// for withdrawn services, we need to set route policies to nil.
		desiredSvcRoutePolicies[svcKey] = nil
	}

	return desiredSvcRoutePolicies, nil
}

func (r *ServiceReconciler) getDesiredSvcRoutePolicies(desiredPeerAdverts PeerAdvertisements, svc *slim_corev1.Service, ls sets.Set[resource.Key]) (ossreconcilerv2.RoutePolicyMap, error) {
	desiredSvcRoutePolicies := make(ossreconcilerv2.RoutePolicyMap)

	for peer, afAdverts := range desiredPeerAdverts {
		for fam, adverts := range afAdverts {
			agentFamily := bgptypes.ToAgentFamily(fam)

			for _, advert := range adverts {
				labelSelector, err := slim_metav1.LabelSelectorAsSelector(advert.Selector)
				if err != nil {
					return nil, fmt.Errorf("failed constructing LabelSelector: %w", err)
				}
				if !labelSelector.Matches(serviceLabelSet(svc)) {
					continue
				}
				for _, advertType := range []v2.BGPServiceAddressType{v2.BGPLoadBalancerIPAddr, v2.BGPExternalIPAddr, v2.BGPClusterIPAddr} {
					policy, err := r.getServiceRoutePolicy(peer, agentFamily, svc, advert, advertType, ls)
					if err != nil {
						return nil, fmt.Errorf("failed to get desired %s route policy: %w", advertType, err)
					}
					if policy != nil {
						existingPolicy := desiredSvcRoutePolicies[policy.Name]
						if existingPolicy != nil {
							policy, err = MergePolicies(existingPolicy, policy)
							if err != nil {
								return nil, fmt.Errorf("failed to merge %s route policies: %w", advertType, err)
							}
						}
						desiredSvcRoutePolicies[policy.Name] = policy
					}
				}
			}
		}
	}

	return desiredSvcRoutePolicies, nil
}

func (r *ServiceReconciler) getServiceRoutePolicy(peer PeerID, family bgptypes.Family, svc *slim_corev1.Service, advert v1.BGPAdvertisement, advertType v2.BGPServiceAddressType, ls sets.Set[resource.Key]) (*bgptypes.RoutePolicy, error) {
	if peer.Address == "" {
		return nil, nil // peer address not known yet
	}
	peerAddr, err := netip.ParseAddr(peer.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse peer address: %w", err)
	}

	valid, err := checkServiceAdvertisement(advert, advertType)
	if err != nil {
		return nil, fmt.Errorf("failed to check %s advertisement: %w", advertType, err)
	}
	if !valid {
		return nil, nil
	}

	var svcPrefixes []netip.Prefix
	switch advertType {
	case v2.BGPLoadBalancerIPAddr:
		svcPrefixes = r.getLBSvcPaths(svc, ls, advert)
	case v2.BGPExternalIPAddr:
		svcPrefixes = r.getExternalIPPaths(svc, ls, advert)
	case v2.BGPClusterIPAddr:
		svcPrefixes = r.getClusterIPPaths(svc, ls, advert)
	}

	var v4Prefixes, v6Prefixes bgptypes.PolicyPrefixMatchList
	for _, prefix := range svcPrefixes {
		if family.Afi == bgptypes.AfiIPv4 && prefix.Addr().Is4() {
			v4Prefixes = append(v4Prefixes, &bgptypes.RoutePolicyPrefixMatch{CIDR: prefix, PrefixLenMin: prefix.Bits(), PrefixLenMax: prefix.Bits()})
		}
		if family.Afi == bgptypes.AfiIPv6 && prefix.Addr().Is6() {
			v6Prefixes = append(v6Prefixes, &bgptypes.RoutePolicyPrefixMatch{CIDR: prefix, PrefixLenMin: prefix.Bits(), PrefixLenMax: prefix.Bits()})
		}
	}
	if len(v4Prefixes) == 0 && len(v6Prefixes) == 0 {
		return nil, nil
	}

	attributes := advert.Attributes
	if r.cfg.MaintenanceGracefulShutdownEnabled && r.nodeStatus != NodeReady {
		// advertise with GRACEFUL_SHUTDOWN community
		if advert.Attributes == nil {
			attributes = &v2.BGPAttributes{}
		} else {
			attributes = advert.Attributes.DeepCopy()
		}
		if attributes.Communities == nil {
			attributes.Communities = &v2.BGPCommunities{}
		}
		attributes.Communities.Standard = append(attributes.Communities.Standard, gracefulShutdownCommunityValue)
	}

	policyName := PolicyName(peer.Name, family.Afi.String(), advert.AdvertisementType, fmt.Sprintf("%s-%s-%s", svc.Name, svc.Namespace, advertType))
	policy, err := ossreconcilerv2.CreatePolicy(policyName, peerAddr, v4Prefixes, v6Prefixes, v2.BGPAdvertisement{
		Attributes: attributes,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create %s route policy: %w", advertType, err)
	}

	return policy, nil
}

// checkServiceAdvertisement checks if the service advertisement is enabled in the advertisement.
func checkServiceAdvertisement(advert v1.BGPAdvertisement, advertServiceType v2.BGPServiceAddressType) (bool, error) {
	if advert.Service == nil {
		return false, fmt.Errorf("advertisement has no service options")
	}

	// If selector is nil, we do not use this advertisement.
	if advert.Selector == nil {
		return false, nil
	}

	// check service type is enabled in advertisement
	svcTypeEnabled := false
	for _, serviceType := range advert.Service.Addresses {
		if serviceType == advertServiceType {
			svcTypeEnabled = true
			break
		}
	}
	if !svcTypeEnabled {
		return false, nil
	}

	return true, nil
}

func (r *ServiceReconciler) resolveSvcFromEndpoints(eps *k8s.Endpoints) (*slim_corev1.Service, bool, error) {
	k := resource.Key{
		Name:      eps.ServiceName.Name(),
		Namespace: eps.ServiceName.Namespace(),
	}
	return r.svcDiffStore.GetByKey(k)
}

func (r *ServiceReconciler) diffID(instanceName string) string {
	return fmt.Sprintf("%s-%s", r.Name(), instanceName)
}

func (r *ServiceReconciler) getPrefixLength(svc *slim_corev1.Service, addr netip.Addr, advert v1.BGPAdvertisement, addrType v2.BGPServiceAddressType) int {
	prefixLen := addr.BitLen()

	if addrType == v2.BGPClusterIPAddr {
		// for iTP=Local, we always use the full prefix length
		if svc.Spec.InternalTrafficPolicy != nil && *svc.Spec.InternalTrafficPolicy == slim_corev1.ServiceInternalTrafficPolicyLocal {
			return prefixLen
		}
	} else {
		// for eTP=Local, we always use the full prefix length
		if svc.Spec.ExternalTrafficPolicy == slim_corev1.ServiceExternalTrafficPolicyLocal {
			return prefixLen
		}
	}

	if advert.Service.AggregationLengthIPv4 != nil && addr.Is4() {
		// guard against invalid prefix length
		if *advert.Service.AggregationLengthIPv4 > 31 || *advert.Service.AggregationLengthIPv4 < 1 {
			r.logger.Warn("Invalid aggregation length for IPv4 address, using /32 prefix length",
				types.ServiceIDLogField, svc.Name,
				types.PrefixLengthLogField, *advert.Service.AggregationLengthIPv4,
			)
			return prefixLen
		}
		prefixLen = int(*advert.Service.AggregationLengthIPv4)
	}

	if advert.Service.AggregationLengthIPv6 != nil && addr.Is6() {
		// guard against invalid prefix length
		if *advert.Service.AggregationLengthIPv6 > 127 || *advert.Service.AggregationLengthIPv6 < 1 {
			r.logger.Warn("Invalid aggregation length for IPv6 address, using /128 prefix length",
				types.ServiceIDLogField, svc.Name,
				types.PrefixLengthLogField, *advert.Service.AggregationLengthIPv6,
			)
			return prefixLen
		}
		prefixLen = int(*advert.Service.AggregationLengthIPv6)
	}

	return prefixLen
}

func svcProtocolToLBL4Type(svcProto slim_corev1.Protocol) loadbalancer.L4Type {
	switch svcProto {
	case slim_corev1.ProtocolUDP:
		return loadbalancer.UDP
	case slim_corev1.ProtocolSCTP:
		return loadbalancer.SCTP
	default:
		return loadbalancer.TCP
	}
}

func parseServiceID(svc *slim_corev1.Service) loadbalancer.ServiceName {
	return loadbalancer.NewServiceName(svc.Namespace, svc.Name)
}
