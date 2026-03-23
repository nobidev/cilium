//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package extlb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	k8sBackendClusterFinalizer  = "lbk8sbackendcluster.isovalent.com/finalizer"
	k8sBackendClusterAnnotation = "lbk8sbackendcluster.isovalent.com/cluster"

	labelCluster         = "lbk8sbackendcluster.isovalent.com/cluster"
	labelSourceNamespace = "lbk8sbackendcluster.isovalent.com/source-namespace"
	labelSourceName      = "lbk8sbackendcluster.isovalent.com/source-name"

	maxResourceNameLen = 63
	hashSuffixLen      = 12
)

// resourceName takes any number of strings and combines them with "-",
// truncating the entire string in the process. Add a hash suffix to help ensure
// uniqueness when two different inputs result in the same truncated string.
func resourceName(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "/")))
	suffix := hex.EncodeToString(h[:hashSuffixLen/2])

	prefix := strings.Join(parts, "-")

	// Collapse runs of hyphens resulting from source names that start or end
	// with hyphens
	for strings.Contains(prefix, "--") {
		prefix = strings.ReplaceAll(prefix, "--", "-")
	}

	maxPrefix := maxResourceNameLen - 1 - hashSuffixLen
	if len(prefix) > maxPrefix {
		prefix = prefix[:maxPrefix]
	}
	prefix = strings.TrimRight(prefix, "-.")

	return prefix + "-" + suffix
}

type lbK8sBackendClusterReconciler struct {
	logger               *slog.Logger
	client               client.Client
	scheme               *runtime.Scheme
	remoteClusterManager *remoteClusterManager
	config               Config

	// remoteClusterSource is an event source for remote cluster changes
	remoteClusterSource *remoteClusterEventSource
}

// remoteClusterEventSource is a source.Source implementation that queues
// reconcile requests when services or nodes change in remote clusters.
type remoteClusterEventSource struct {
	logger *slog.Logger

	ctx   context.Context
	queue workqueue.TypedRateLimitingInterface[ctrl.Request]
}

func (s *remoteClusterEventSource) Start(
	ctx context.Context,
	queue workqueue.TypedRateLimitingInterface[ctrl.Request],
) error {
	s.ctx = ctx
	s.queue = queue
	return nil
}

func (s *remoteClusterEventSource) onClusterChange(clusterName string) {
	if s.ctx == nil || s.queue == nil {
		// Controller not started yet
		return
	}

	s.logger.Debug("queueing update from remote cluster change",
		logfields.ClusterName, clusterName)
	s.queue.Add(ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name: clusterName,
		},
	})
}

func newLBK8sBackendClusterReconciler(
	logger *slog.Logger,
	client client.Client,
	scheme *runtime.Scheme,
	remoteClusterManager *remoteClusterManager,
	config Config,
) *lbK8sBackendClusterReconciler {
	controllerLogger := logger.With(logfields.Controller, "lbk8sbackendcluster")
	source := &remoteClusterEventSource{
		logger: controllerLogger,
	}

	r := &lbK8sBackendClusterReconciler{
		logger:               controllerLogger,
		client:               client,
		scheme:               scheme,
		remoteClusterManager: remoteClusterManager,
		config:               config,
		remoteClusterSource:  source,
	}

	remoteClusterManager.SetServiceChangeCallback(source.onClusterChange)
	remoteClusterManager.SetDisconnectCallback(source.onClusterChange)

	return r
}

func (r *lbK8sBackendClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&isovalentv1alpha1.LBK8sBackendCluster{}).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findLBK8sBackendClustersForSecret),
		).
		WatchesRawSource(r.remoteClusterSource).
		Owns(&isovalentv1alpha1.LBService{}).
		Owns(&isovalentv1alpha1.LBVIP{}).
		Owns(&isovalentv1alpha1.LBBackendPool{}).
		Complete(r)
}

// findLBK8sBackendClustersForSecret finds all LBK8sBackendCluster resources that
// reference a given Secret.
func (r *lbK8sBackendClusterReconciler) findLBK8sBackendClustersForSecret(ctx context.Context, obj client.Object) []reconcile.Request {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return nil
	}

	var clusterList isovalentv1alpha1.LBK8sBackendClusterList
	if err := r.client.List(ctx, &clusterList); err != nil {
		r.logger.Error("failed to list LBK8sBackendClusters", logfields.Error, err)
		return nil
	}

	var requests []reconcile.Request
	for _, cluster := range clusterList.Items {
		if cluster.Spec.Authentication.SecretRef.Name == secret.Name &&
			cluster.Spec.Authentication.SecretRef.Namespace == secret.Namespace {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name: cluster.Name,
				},
			})
		}
	}
	return requests
}

func (r *lbK8sBackendClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.logger.With(logfields.Resource, req.NamespacedName)

	var cluster isovalentv1alpha1.LBK8sBackendCluster
	if err := r.client.Get(ctx, req.NamespacedName, &cluster); err != nil {
		if k8serrors.IsNotFound(err) {
			// No such cluster, stop the watcher
			r.remoteClusterManager.Stop(req.Name)
			return controllerruntime.Success()
		}
		logger.Error("failed to get LBK8sBackendCluster", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	if !cluster.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, &cluster, logger)
	}

	if !controllerutil.ContainsFinalizer(&cluster, k8sBackendClusterFinalizer) {
		controllerutil.AddFinalizer(&cluster, k8sBackendClusterFinalizer)
		if err := r.client.Update(ctx, &cluster); err != nil {
			logger.Error("failed to add finalizer", logfields.Error, err)
			return controllerruntime.Fail(err)
		}
		return controllerruntime.Success()
	}

	secret, err := r.getAuthSecret(ctx, &cluster)
	if err != nil {
		return r.updateStatusError(ctx, &cluster, logger, isovalentv1alpha1.ClusterConnectedReasonAuthenticationError,
			fmt.Sprintf("failed to get authentication secret: %v", err))
	}

	if err := r.remoteClusterManager.EnsureCluster(ctx, &cluster, secret); err != nil {
		return r.updateStatusError(ctx, &cluster, logger, isovalentv1alpha1.ClusterConnectedReasonConnectionError,
			fmt.Sprintf("failed to connect to remote cluster: %v", err))
	}

	discoveredServices, err := r.syncRemoteServices(ctx, &cluster, logger)
	if err != nil {
		return r.updateStatusError(ctx, &cluster, logger, isovalentv1alpha1.ClusterConnectedReasonSyncError,
			fmt.Sprintf("failed to sync remote services: %v", err))
	}

	return r.updateStatusSuccess(ctx, &cluster, logger, discoveredServices)
}

func (r *lbK8sBackendClusterReconciler) handleDeletion(
	ctx context.Context,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
	logger *slog.Logger,
) (ctrl.Result, error) {
	logger.Info("handling deletion of LBK8sBackendCluster")

	// Make a best-effort to clean up ingress IPs and annotations we wrote to
	// remote services before tearing down the connection.
	if err := r.cleanupRemoteServiceIngress(ctx, cluster, logger); err != nil {
		logger.Warn("failed to cleanup remote service ingress entries", logfields.Error, err)
	}

	r.remoteClusterManager.Stop(cluster.Name)

	if err := r.cleanupILBResources(ctx, cluster); err != nil {
		logger.Error("failed to cleanup ILB resources", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	if cluster.Spec.TargetNamespace == nil {
		nsName := getTargetNamespace(cluster)
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: nsName,
			},
		}
		logger.Info("deleting auto-created namespace", logfields.K8sNamespace, nsName)
		if err := r.client.Delete(ctx, ns); err != nil && !k8serrors.IsNotFound(err) {
			logger.Error("failed to delete auto-created namespace",
				logfields.K8sNamespace, nsName,
				logfields.Error, err,
			)
			return controllerruntime.Fail(err)
		}
	}

	controllerutil.RemoveFinalizer(cluster, k8sBackendClusterFinalizer)
	if err := r.client.Update(ctx, cluster); err != nil {
		logger.Error("failed to remove finalizer", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	return controllerruntime.Success()
}

func (r *lbK8sBackendClusterReconciler) getAuthSecret(
	ctx context.Context,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
) (*corev1.Secret, error) {
	var secret corev1.Secret
	if err := r.client.Get(ctx, types.NamespacedName{
		Name:      cluster.Spec.Authentication.SecretRef.Name,
		Namespace: cluster.Spec.Authentication.SecretRef.Namespace,
	}, &secret); err != nil {
		return nil, err
	}
	return &secret, nil
}

func getTargetNamespace(cluster *isovalentv1alpha1.LBK8sBackendCluster) string {
	if cluster.Spec.TargetNamespace != nil {
		return *cluster.Spec.TargetNamespace
	}
	return resourceName("extlb", cluster.Name)
}

func (r *lbK8sBackendClusterReconciler) ensureNamespace(
	ctx context.Context,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
	name string,
	logger *slog.Logger,
) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	result, err := controllerutil.CreateOrUpdate(ctx, r.client, ns, func() error {
		if ns.Labels == nil {
			ns.Labels = make(map[string]string)
		}
		ns.Labels[labelCluster] = cluster.Name
		return nil
	})
	if err != nil {
		return err
	}
	if result == controllerutil.OperationResultCreated {
		logger.Info("creating target namespace", logfields.K8sNamespace, name)
	}
	return nil
}

// syncRemoteServices syncs LoadBalancer services from the remote cluster
// and creates corresponding ILB resources.
func (r *lbK8sBackendClusterReconciler) syncRemoteServices(
	ctx context.Context,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
	logger *slog.Logger,
) ([]isovalentv1alpha1.LBK8sBackendClusterDiscoveredService, error) {
	remoteClient, err := r.remoteClusterManager.GetClient(cluster.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get remote cluster client: %w", err)
	}

	targetNamespace := getTargetNamespace(cluster)
	if cluster.Spec.TargetNamespace == nil {
		if err := r.ensureNamespace(ctx, cluster, targetNamespace, logger); err != nil {
			return nil, fmt.Errorf("failed to ensure target namespace %q: %w", targetNamespace, err)
		}
	}

	servicesWithConfigs, err := r.discoverServices(ctx, remoteClient, cluster, logger)
	if err != nil {
		return nil, err
	}

	nodeIPs, err := r.getNodeIPs(ctx, remoteClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get remote node IPs: %w", err)
	}

	var discoveredServices []isovalentv1alpha1.LBK8sBackendClusterDiscoveredService

	for _, svcWithConfig := range servicesWithConfigs {
		svc := svcWithConfig.service
		discoveryConfig := svcWithConfig.discoveryConfig

		discovered, err := r.syncService(ctx, cluster, remoteClient, &svc, discoveryConfig, targetNamespace, nodeIPs, logger)
		if err != nil {
			logger.Error("failed to sync service",
				logfields.K8sNamespace, svc.Namespace,
				logfields.ServiceName, svc.Name,
				logfields.Error, err,
			)
		}
		discoveredServices = append(discoveredServices, discovered)
	}

	if err := r.cleanupOrphanedResources(ctx, cluster, discoveredServices, logger); err != nil {
		logger.Error("failed to cleanup orphaned resources", logfields.Error, err)
	}

	return discoveredServices, nil
}

type discoveredServiceWithConfig struct {
	service         corev1.Service
	discoveryConfig *isovalentv1alpha1.LBK8sBackendClusterServiceDiscoveryConfig
}

// discoverServices discovers LoadBalancer services from the remote cluster by
// iterating through all ServiceDiscovery configurations. When no configurations
// are provided, all LoadBalancer services are discovered by using a catch-all
// config with no filters.
func (r *lbK8sBackendClusterReconciler) discoverServices(
	ctx context.Context,
	remoteClient client.Client,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
	logger *slog.Logger,
) ([]discoveredServiceWithConfig, error) {
	configs := cluster.Spec.ServiceDiscovery

	// Having zero DiscoveryConfigs is a special case. We add a single empty
	// catch-all config with no filters, which results in all LoadBalancer
	// services in all Namespaces being discovered.
	if len(configs) == 0 {
		configs = []isovalentv1alpha1.LBK8sBackendClusterServiceDiscoveryConfig{{}}
	}

	discoveredMap := make(map[string]discoveredServiceWithConfig)

	for _, discoveryConfig := range configs {
		services, err := r.discoverServicesForConfig(ctx, remoteClient, cluster, &discoveryConfig, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to discover services for config %q: %w",
				discoveryConfig.Name, err)
		}

		for _, svc := range services {
			key := fmt.Sprintf("%s/%s", svc.Namespace, svc.Name)
			if _, exists := discoveredMap[key]; !exists {
				// We use a map to ensure that each service is discovered only
				// once, and that the order of discovery is based on the order
				// of the configs.
				discoveredMap[key] = discoveredServiceWithConfig{
					service:         svc,
					discoveryConfig: &discoveryConfig,
				}
			}
		}
	}

	// After building the map of services with their corresponding configs, we
	// convert it into a sorted slice
	keys := make([]string, 0, len(discoveredMap))
	for k := range discoveredMap {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	result := make([]discoveredServiceWithConfig, 0, len(discoveredMap))
	for _, k := range keys {
		result = append(result, discoveredMap[k])
	}

	return result, nil
}

// discoverServicesForConfig discovers services matching a single DiscoveryConfig
func (r *lbK8sBackendClusterReconciler) discoverServicesForConfig(
	ctx context.Context,
	remoteClient client.Client,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
	config *isovalentv1alpha1.LBK8sBackendClusterServiceDiscoveryConfig,
	logger *slog.Logger,
) ([]corev1.Service, error) {
	var serviceList corev1.ServiceList
	listOpts := []client.ListOption{}

	if len(config.Namespaces) == 1 {
		listOpts = append(listOpts, client.InNamespace(config.Namespaces[0]))
	}

	if config.LabelSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(config.LabelSelector)
		if err != nil {
			return nil, fmt.Errorf("invalid label selector: %w", err)
		}
		listOpts = append(listOpts, client.MatchingLabelsSelector{Selector: selector})
	}

	if err := remoteClient.List(ctx, &serviceList, listOpts...); err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	var eligibleServices []corev1.Service
	for _, svc := range serviceList.Items {
		if len(config.Namespaces) > 1 {
			if !slices.Contains(config.Namespaces, svc.Namespace) {
				continue
			}
		}

		if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
			continue
		}

		managedByUs := svc.Annotations != nil && svc.Annotations[k8sBackendClusterAnnotation] == cluster.Name
		hasExternalIP := len(svc.Status.LoadBalancer.Ingress) > 0

		if hasExternalIP && !managedByUs {
			continue
		}

		logger.Debug("discovered eligible service",
			logfields.K8sNamespace, svc.Namespace,
			logfields.ServiceName, svc.Name,
			logfields.DiscoveryConfig, config.Name,
		)
		eligibleServices = append(eligibleServices, svc)
	}

	return eligibleServices, nil
}

// syncService syncs a single service from the remote cluster, creating
// the necessary ILB resources. It creates one LBVIP shared across all ports,
// and also one LBBackendPool + LBService per port.
func (r *lbK8sBackendClusterReconciler) syncService(
	ctx context.Context,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
	remoteClient client.Client,
	remoteSvc *corev1.Service,
	discoveryConfig *isovalentv1alpha1.LBK8sBackendClusterServiceDiscoveryConfig,
	targetNamespace string,
	nodeIPs []string,
	logger *slog.Logger,
) (isovalentv1alpha1.LBK8sBackendClusterDiscoveredService, error) {
	logger = logger.With(
		logfields.K8sNamespace, remoteSvc.Namespace,
		logfields.ServiceName, remoteSvc.Name,
		logfields.DiscoveryConfig, discoveryConfig.Name,
	)
	logger.Debug("syncing remote service")

	errResult := isovalentv1alpha1.LBK8sBackendClusterDiscoveredService{
		RemoteNamespace:     remoteSvc.Namespace,
		RemoteName:          remoteSvc.Name,
		DiscoveryConfigName: discoveryConfig.Name,
		Status:              string(isovalentv1alpha1.LBK8sBackendClusterDiscoveredServiceStatusError),
	}

	if len(remoteSvc.Spec.Ports) == 0 {
		err := fmt.Errorf("service has no ports")
		errResult.LastError = ptr.To(err.Error())
		return errResult, err
	}

	var tcpPorts []corev1.ServicePort
	for _, port := range remoteSvc.Spec.Ports {
		if port.NodePort != 0 && port.Protocol == corev1.ProtocolTCP {
			tcpPorts = append(tcpPorts, port)
		}
	}
	if len(tcpPorts) == 0 {
		err := fmt.Errorf("service has no eligible TCP ports with NodePort")
		errResult.LastError = ptr.To(err.Error())
		return errResult, err
	}

	vipName := resourceName(remoteSvc.Namespace, remoteSvc.Name)

	vip, err := r.ensureLBVIP(ctx, cluster, remoteSvc, targetNamespace, vipName, logger)
	if err != nil {
		errResult.LastError = ptr.To(fmt.Sprintf("failed to create LBVIP: %v", err))
		return errResult, err
	}

	vipRef := &isovalentv1alpha1.LBExternalLBResourceRef{
		Namespace: vip.Namespace,
		Name:      vip.Name,
	}

	var poolRefs []isovalentv1alpha1.LBExternalLBResourceRef
	var svcRefs []isovalentv1alpha1.LBExternalLBResourceRef

	for _, port := range tcpPorts {
		portResourceName := resourceName(remoteSvc.Namespace, remoteSvc.Name, fmt.Sprintf("%d", port.Port))

		pool, err := r.ensureLBBackendPool(ctx, cluster, remoteSvc, discoveryConfig,
			targetNamespace, portResourceName, nodeIPs, port.NodePort, logger)
		if err != nil {
			errResult.LastError = ptr.To(fmt.Sprintf("failed to create LBBackendPool for port %d: %v", port.Port, err))
			errResult.LBVIPRef = vipRef
			errResult.LBBackendPoolRefs = poolRefs
			errResult.LBServiceRefs = svcRefs
			return errResult, err
		}
		poolRefs = append(poolRefs, isovalentv1alpha1.LBExternalLBResourceRef{
			Namespace: pool.Namespace,
			Name:      pool.Name,
		})

		lbsvc, err := r.ensureLBService(ctx, cluster, remoteSvc, targetNamespace,
			portResourceName, port.Port, vip.Name, pool.Name, logger)
		if err != nil {
			errResult.LastError = ptr.To(fmt.Sprintf("failed to create LBService for port %d: %v", port.Port, err))
			errResult.LBVIPRef = vipRef
			errResult.LBBackendPoolRefs = poolRefs
			errResult.LBServiceRefs = svcRefs
			return errResult, err
		}
		svcRefs = append(svcRefs, isovalentv1alpha1.LBExternalLBResourceRef{
			Namespace: lbsvc.Namespace,
			Name:      lbsvc.Name,
		})
	}

	var externalIP *string
	if vip.Status.Addresses.IPv4 != nil && *vip.Status.Addresses.IPv4 != "" {
		externalIP = vip.Status.Addresses.IPv4
		if err := r.updateRemoteServiceExternalIP(ctx, remoteClient, cluster, remoteSvc, *externalIP, logger); err != nil {
			logger.Warn("failed to update remote service external IP", logfields.Error, err)
		}
	}

	return isovalentv1alpha1.LBK8sBackendClusterDiscoveredService{
		RemoteNamespace:     remoteSvc.Namespace,
		RemoteName:          remoteSvc.Name,
		DiscoveryConfigName: discoveryConfig.Name,
		Status:              string(isovalentv1alpha1.LBK8sBackendClusterDiscoveredServiceStatusSynced),
		ExternalIP:          externalIP,
		LBServiceRefs:       svcRefs,
		LBVIPRef:            vipRef,
		LBBackendPoolRefs:   poolRefs,
	}, nil
}

func (r *lbK8sBackendClusterReconciler) getNodeIPs(
	ctx context.Context,
	remoteClient client.Client,
) ([]string, error) {
	var nodeList corev1.NodeList
	if err := remoteClient.List(ctx, &nodeList); err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	if len(nodeList.Items) == 0 {
		return nil, fmt.Errorf("no nodes found in remote cluster")
	}

	var nodeIPs []string
	for _, node := range nodeList.Items {
		for _, addr := range node.Status.Addresses {
			if addr.Type == corev1.NodeInternalIP {
				nodeIPs = append(nodeIPs, addr.Address)
				break
			}
		}
	}

	if len(nodeIPs) == 0 {
		return nil, fmt.Errorf("no internal IPs found for any node")
	}

	return nodeIPs, nil
}

func (r *lbK8sBackendClusterReconciler) ensureLBVIP(
	ctx context.Context,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
	remoteSvc *corev1.Service,
	namespace string,
	name string,
	logger *slog.Logger,
) (*isovalentv1alpha1.LBVIP, error) {
	vip := &isovalentv1alpha1.LBVIP{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}

	result, err := controllerutil.CreateOrUpdate(ctx, r.client, vip, func() error {
		vip.Labels = map[string]string{
			labelCluster:         cluster.Name,
			labelSourceNamespace: remoteSvc.Namespace,
			labelSourceName:      remoteSvc.Name,
		}
		return controllerutil.SetControllerReference(cluster, vip, r.scheme)
	})
	if err != nil {
		return nil, err
	}

	if result == controllerutil.OperationResultCreated {
		logger.Info("creating LBVIP", logfields.ResourceName, name)
	}

	return vip, nil
}

func (r *lbK8sBackendClusterReconciler) ensureLBBackendPool(
	ctx context.Context,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
	remoteSvc *corev1.Service,
	discoveryConfig *isovalentv1alpha1.LBK8sBackendClusterServiceDiscoveryConfig,
	namespace string,
	name string,
	nodeIPs []string,
	nodePort int32,
	logger *slog.Logger,
) (*isovalentv1alpha1.LBBackendPool, error) {
	healthCheck := isovalentv1alpha1.HealthCheck{
		TCP: &isovalentv1alpha1.HealthCheckTCP{},
	}

	if discoveryConfig.HealthCheck != nil {
		if discoveryConfig.HealthCheck.IntervalSeconds != nil {
			healthCheck.IntervalSeconds = discoveryConfig.HealthCheck.IntervalSeconds
		}
		if discoveryConfig.HealthCheck.TimeoutSeconds != nil {
			healthCheck.TimeoutSeconds = discoveryConfig.HealthCheck.TimeoutSeconds
		}
	}

	backends := make([]isovalentv1alpha1.Backend, 0, len(nodeIPs))
	for _, ip := range nodeIPs {
		backends = append(backends, isovalentv1alpha1.Backend{
			IP:   &ip,
			Port: nodePort,
		})
	}

	pool := &isovalentv1alpha1.LBBackendPool{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}

	result, err := controllerutil.CreateOrUpdate(ctx, r.client, pool, func() error {
		pool.Labels = map[string]string{
			labelCluster:         cluster.Name,
			labelSourceNamespace: remoteSvc.Namespace,
			labelSourceName:      remoteSvc.Name,
		}
		pool.Spec = isovalentv1alpha1.LBBackendPoolSpec{
			BackendType: isovalentv1alpha1.BackendTypeIP,
			Backends:    backends,
			HealthCheck: healthCheck,
		}
		return controllerutil.SetControllerReference(cluster, pool, r.scheme)
	})
	if err != nil {
		return nil, err
	}

	if result == controllerutil.OperationResultCreated {
		logger.Info("creating LBBackendPool",
			logfields.ResourceName, name,
			logfields.Backends, len(backends),
			logfields.Port, nodePort,
		)
	}

	return pool, nil
}

func (r *lbK8sBackendClusterReconciler) ensureLBService(
	ctx context.Context,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
	remoteSvc *corev1.Service,
	namespace string,
	name string,
	port int32,
	vipName string,
	poolName string,
	logger *slog.Logger,
) (*isovalentv1alpha1.LBService, error) {
	lbsvc := &isovalentv1alpha1.LBService{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}

	result, err := controllerutil.CreateOrUpdate(ctx, r.client, lbsvc, func() error {
		lbsvc.Labels = map[string]string{
			labelCluster:         cluster.Name,
			labelSourceNamespace: remoteSvc.Namespace,
			labelSourceName:      remoteSvc.Name,
		}
		lbsvc.Spec = isovalentv1alpha1.LBServiceSpec{
			VIPRef: isovalentv1alpha1.LBServiceVIPRef{
				Name: vipName,
			},
			Port: port,
			Applications: isovalentv1alpha1.LBServiceApplications{
				TCPProxy: &isovalentv1alpha1.LBServiceApplicationTCPProxy{
					Routes: []isovalentv1alpha1.LBServiceTCPRoute{
						{
							BackendRef: isovalentv1alpha1.LBServiceBackendRef{
								Name: poolName,
							},
						},
					},
				},
			},
		}
		return controllerutil.SetControllerReference(cluster, lbsvc, r.scheme)
	})
	if err != nil {
		return nil, err
	}

	if result == controllerutil.OperationResultCreated {
		logger.Info("creating LBService",
			logfields.ResourceName, name,
			logfields.VIP, vipName,
			logfields.Pool, poolName,
		)
	}

	return lbsvc, nil
}

func (r *lbK8sBackendClusterReconciler) updateRemoteServiceExternalIP(
	ctx context.Context,
	remoteClient client.Client,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
	remoteSvc *corev1.Service,
	externalIP string,
	logger *slog.Logger,
) error {
	logger.Debug("updateRemoteServiceExternalIP called",
		logfields.K8sNamespace, remoteSvc.Namespace,
		logfields.ServiceName, remoteSvc.Name,
		logfields.IPAddr, externalIP,
	)

	var current corev1.Service
	if err := remoteClient.Get(ctx, types.NamespacedName{
		Name:      remoteSvc.Name,
		Namespace: remoteSvc.Namespace,
	}, &current); err != nil {
		return err
	}

	if current.Annotations == nil || current.Annotations[k8sBackendClusterAnnotation] != cluster.Name {
		annotationPatch := fmt.Appendf(nil,
			`{"metadata":{"annotations":{%q:%q}}}`,
			k8sBackendClusterAnnotation, cluster.Name,
		)
		if err := remoteClient.Patch(ctx, &current, client.RawPatch(types.MergePatchType, annotationPatch)); err != nil {
			return fmt.Errorf("failed to patch service annotation: %w", err)
		}
	}

	for _, ingress := range current.Status.LoadBalancer.Ingress {
		if ingress.IP == externalIP {
			return nil
		}
	}

	logger.Info("updating remote service external IP",
		logfields.K8sNamespace, remoteSvc.Namespace,
		logfields.ServiceName, remoteSvc.Name,
		logfields.IPAddr, externalIP,
	)

	// Build a new ingress list that preserves any existing entries and ensures
	// our IP is present. A merge patch on an array replaces the entire list, so
	// we must include all existing entries.
	ingress := make([]corev1.LoadBalancerIngress, 0, len(current.Status.LoadBalancer.Ingress)+1)
	ingress = append(ingress, current.Status.LoadBalancer.Ingress...)
	ingress = append(ingress, corev1.LoadBalancerIngress{IP: externalIP})

	current.Status.LoadBalancer.Ingress = ingress
	return remoteClient.Status().Update(ctx, &current)
}

// cleanupRemoteServiceIngress removes the external IPs and annotations that
// this controller wrote to remote services. It must be called before the remote
// cluster connection is torn down. Errors are returned but we treat them as
// best-effort since the remote cluster may already be unreachable.
func (r *lbK8sBackendClusterReconciler) cleanupRemoteServiceIngress(
	ctx context.Context,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
	logger *slog.Logger,
) error {
	remoteClient, err := r.remoteClusterManager.GetClient(cluster.Name)
	if err != nil {
		return fmt.Errorf("remote cluster not connected: %w", err)
	}

	// Collect allocated VIPs from local LBVIP resources so we know which
	// ingress IPs to strip from the remote services.
	var lbVIPs isovalentv1alpha1.LBVIPList
	if err := r.client.List(ctx, &lbVIPs, client.MatchingLabels{labelCluster: cluster.Name}); err != nil {
		return fmt.Errorf("failed to list local LBVIPs: %w", err)
	}
	ourIPs := make(map[string]struct{})
	for _, vip := range lbVIPs.Items {
		if vip.Status.Addresses.IPv4 != nil && *vip.Status.Addresses.IPv4 != "" {
			ourIPs[*vip.Status.Addresses.IPv4] = struct{}{}
		}
		if vip.Status.Addresses.IPv6 != nil && *vip.Status.Addresses.IPv6 != "" {
			ourIPs[*vip.Status.Addresses.IPv6] = struct{}{}
		}
	}

	// List remote services we've annotated.
	var serviceList corev1.ServiceList
	if err := remoteClient.List(ctx, &serviceList); err != nil {
		return fmt.Errorf("failed to list remote services: %w", err)
	}

	var errs []error
	for _, svc := range serviceList.Items {
		if svc.Annotations == nil || svc.Annotations[k8sBackendClusterAnnotation] != cluster.Name {
			continue
		}

		// Remove our IPs from the ingress list.
		var filtered []corev1.LoadBalancerIngress
		for _, ing := range svc.Status.LoadBalancer.Ingress {
			if _, ours := ourIPs[ing.IP]; !ours {
				filtered = append(filtered, ing)
			}
		}

		if len(filtered) != len(svc.Status.LoadBalancer.Ingress) {
			svc.Status.LoadBalancer.Ingress = filtered
			if err := remoteClient.Status().Update(ctx, &svc); err != nil {
				errs = append(errs, fmt.Errorf("failed to update ingress for %s/%s: %w", svc.Namespace, svc.Name, err))
				continue
			}
			logger.Info("removed external IP from remote service",
				logfields.K8sNamespace, svc.Namespace,
				logfields.ServiceName, svc.Name,
			)
		}

		// Remove the annotation. Re-fetch to avoid conflict after writing status above.
		if err := remoteClient.Get(ctx, types.NamespacedName{
			Name:      svc.Name,
			Namespace: svc.Namespace,
		}, &svc); err != nil {
			errs = append(errs, err)
			continue
		}
		annotationPatch := fmt.Appendf(nil,
			`{"metadata":{"annotations":{%q:null}}}`,
			k8sBackendClusterAnnotation,
		)
		if err := remoteClient.Patch(ctx, &svc, client.RawPatch(types.MergePatchType, annotationPatch)); err != nil {
			errs = append(errs, fmt.Errorf("failed to remove annotation from %s/%s: %w", svc.Namespace, svc.Name, err))
		}
	}

	return errors.Join(errs...)
}

// cleanupILBResources cleans up ILB resources created for an LBK8sBackendCluster.
// It lists then deletes across all namespaces by label, which handles the case
// where the target namespace was changed between reconciliations.
// We use list+delete instead of DeleteAllOf because controller-runtime cannot
// perform DeleteAllOf across all namespaces for namespaced resources.
func (r *lbK8sBackendClusterReconciler) cleanupILBResources(
	ctx context.Context,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
) error {
	clusterLabels := client.MatchingLabels{
		labelCluster: cluster.Name,
	}

	var errs []error

	var lbServices isovalentv1alpha1.LBServiceList
	if err := r.client.List(ctx, &lbServices, clusterLabels); err != nil {
		errs = append(errs, err)
	} else {
		for _, svc := range lbServices.Items {
			if err := r.client.Delete(ctx, &svc); err != nil && !k8serrors.IsNotFound(err) {
				errs = append(errs, err)
			}
		}
	}

	var lbPools isovalentv1alpha1.LBBackendPoolList
	if err := r.client.List(ctx, &lbPools, clusterLabels); err != nil {
		errs = append(errs, err)
	} else {
		for _, pool := range lbPools.Items {
			if err := r.client.Delete(ctx, &pool); err != nil && !k8serrors.IsNotFound(err) {
				errs = append(errs, err)
			}
		}
	}

	var lbVIPs isovalentv1alpha1.LBVIPList
	if err := r.client.List(ctx, &lbVIPs, clusterLabels); err != nil {
		errs = append(errs, err)
	} else {
		for _, vip := range lbVIPs.Items {
			if err := r.client.Delete(ctx, &vip); err != nil && !k8serrors.IsNotFound(err) {
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
}

// cleanupOrphanedResources cleans up ILB resources for services that no longer exist.
// It independently scans LBServices, LBBackendPools, and LBVIPs since per-port
// resources have different names than the shared VIP.
func (r *lbK8sBackendClusterReconciler) cleanupOrphanedResources(
	ctx context.Context,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
	currentServices []isovalentv1alpha1.LBK8sBackendClusterDiscoveredService,
	logger *slog.Logger,
) error {
	// Build sets of expected resource names from the refs produced during sync.
	// This catches both whole-service removal and individual port removal,
	// where the service key stays but some per-port resources need to be
	// removed.
	expectedLBServices := make(map[string]struct{})
	expectedLBPools := make(map[string]struct{})
	expectedLBVIPs := make(map[string]struct{})
	for _, svc := range currentServices {
		for _, ref := range svc.LBServiceRefs {
			expectedLBServices[ref.Namespace+"/"+ref.Name] = struct{}{}
		}
		for _, ref := range svc.LBBackendPoolRefs {
			expectedLBPools[ref.Namespace+"/"+ref.Name] = struct{}{}
		}
		if svc.LBVIPRef != nil {
			expectedLBVIPs[svc.LBVIPRef.Namespace+"/"+svc.LBVIPRef.Name] = struct{}{}
		}
	}

	clusterLabels := client.MatchingLabels{labelCluster: cluster.Name}

	var errs []error

	var lbServices isovalentv1alpha1.LBServiceList
	if err := r.client.List(ctx, &lbServices, clusterLabels); err != nil {
		errs = append(errs, err)
	} else {
		for _, lbsvc := range lbServices.Items {
			key := lbsvc.Namespace + "/" + lbsvc.Name
			if _, exists := expectedLBServices[key]; !exists {
				logger.Info("deleting orphaned LBService",
					logfields.ResourceName, lbsvc.Name,
					logfields.SourceService, lbsvc.Labels[labelSourceNamespace]+"/"+lbsvc.Labels[labelSourceName],
				)
				if err := r.client.Delete(ctx, &lbsvc); err != nil && !k8serrors.IsNotFound(err) {
					logger.Error("failed to delete orphaned LBService",
						logfields.ResourceName, lbsvc.Name,
						logfields.Error, err,
					)
					errs = append(errs, err)
				}
			}
		}
	}

	var lbPools isovalentv1alpha1.LBBackendPoolList
	if err := r.client.List(ctx, &lbPools, clusterLabels); err != nil {
		errs = append(errs, err)
	} else {
		for _, pool := range lbPools.Items {
			key := pool.Namespace + "/" + pool.Name
			if _, exists := expectedLBPools[key]; !exists {
				logger.Info("deleting orphaned LBBackendPool",
					logfields.ResourceName, pool.Name,
					logfields.SourceService, pool.Labels[labelSourceNamespace]+"/"+pool.Labels[labelSourceName],
				)
				if err := r.client.Delete(ctx, &pool); err != nil && !k8serrors.IsNotFound(err) {
					logger.Error("failed to delete orphaned LBBackendPool",
						logfields.ResourceName, pool.Name,
						logfields.Error, err,
					)
					errs = append(errs, err)
				}
			}
		}
	}

	var lbVIPs isovalentv1alpha1.LBVIPList
	if err := r.client.List(ctx, &lbVIPs, clusterLabels); err != nil {
		errs = append(errs, err)
	} else {
		for _, vip := range lbVIPs.Items {
			key := vip.Namespace + "/" + vip.Name
			if _, exists := expectedLBVIPs[key]; !exists {
				logger.Info("deleting orphaned LBVIP",
					logfields.ResourceName, vip.Name,
					logfields.SourceService, vip.Labels[labelSourceNamespace]+"/"+vip.Labels[labelSourceName],
				)
				if err := r.client.Delete(ctx, &vip); err != nil && !k8serrors.IsNotFound(err) {
					logger.Error("failed to delete orphaned LBVIP",
						logfields.ResourceName, vip.Name,
						logfields.Error, err,
					)
					errs = append(errs, err)
				}
			}
		}
	}

	return errors.Join(errs...)
}

func (r *lbK8sBackendClusterReconciler) updateStatusError(
	ctx context.Context,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
	logger *slog.Logger,
	reason string,
	message string,
) (ctrl.Result, error) {
	logger.Error("reconciliation error",
		logfields.Reason, reason,
		logfields.Message, message,
	)

	if cluster.Status == nil {
		cluster.Status = &isovalentv1alpha1.LBK8sBackendClusterStatus{}
	}

	status := isovalentv1alpha1.ExtLBResourceStatusConditionNotMet
	cluster.Status.Status = &status
	cluster.Status.Conditions = removeCondition(cluster.Status.Conditions, isovalentv1alpha1.DeprecatedConditionTypeClusterConnected)
	cluster.Status.Conditions = updateCondition(cluster.Status.Conditions,
		isovalentv1alpha1.ConditionTypeClusterConnected,
		metav1.ConditionFalse,
		reason,
		message,
	)

	if err := r.client.Status().Update(ctx, cluster); err != nil {
		logger.Error("failed to update status", logfields.Error, err)
	}

	return controllerruntime.Fail(fmt.Errorf("%s: %s", reason, message))
}

func (r *lbK8sBackendClusterReconciler) updateStatusSuccess(
	ctx context.Context,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
	logger *slog.Logger,
	discoveredServices []isovalentv1alpha1.LBK8sBackendClusterDiscoveredService,
) (ctrl.Result, error) {
	if cluster.Status == nil {
		cluster.Status = &isovalentv1alpha1.LBK8sBackendClusterStatus{}
	}

	now := metav1.Now()
	status := isovalentv1alpha1.ExtLBResourceStatusOK
	cluster.Status.Status = &status
	cluster.Status.LastSyncTime = &now
	cluster.Status.ServicesDiscovered = int32(len(discoveredServices))
	cluster.Status.DiscoveredServices = discoveredServices
	cluster.Status.Conditions = removeCondition(cluster.Status.Conditions, isovalentv1alpha1.DeprecatedConditionTypeClusterConnected)
	cluster.Status.Conditions = updateCondition(cluster.Status.Conditions,
		isovalentv1alpha1.ConditionTypeClusterConnected,
		metav1.ConditionTrue,
		isovalentv1alpha1.ClusterConnectedReasonConnected,
		"Successfully connected to remote cluster",
	)

	var errorCount int
	for _, svc := range discoveredServices {
		if svc.Status == string(isovalentv1alpha1.LBK8sBackendClusterDiscoveredServiceStatusError) {
			errorCount++
		}
	}

	if errorCount > 0 {
		cluster.Status.Conditions = updateCondition(cluster.Status.Conditions,
			isovalentv1alpha1.ConditionTypeSyncing,
			metav1.ConditionFalse,
			isovalentv1alpha1.SyncingReasonPartialSync,
			fmt.Sprintf("Synced %d services, %d failed", len(discoveredServices)-errorCount, errorCount),
		)
	} else {
		cluster.Status.Conditions = updateCondition(cluster.Status.Conditions,
			isovalentv1alpha1.ConditionTypeSyncing,
			metav1.ConditionTrue,
			isovalentv1alpha1.SyncingReasonSyncing,
			fmt.Sprintf("Successfully synced %d services", len(discoveredServices)),
		)
	}

	if err := r.client.Status().Update(ctx, cluster); err != nil {
		logger.Error("failed to update status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	logger.Info("reconciliation successful",
		logfields.ServiceCount, len(discoveredServices),
	)

	return ctrl.Result{}, nil
}

func removeCondition(conditions []metav1.Condition, conditionType string) []metav1.Condition {
	for i, c := range conditions {
		if c.Type == conditionType {
			return slices.Delete(conditions, i, i+1)
		}
	}
	return conditions
}

func updateCondition(conditions []metav1.Condition, conditionType string, status metav1.ConditionStatus, reason, message string) []metav1.Condition {
	now := metav1.Now()
	for i, c := range conditions {
		if c.Type == conditionType {
			if c.Status != status || c.Reason != reason || c.Message != message {
				conditions[i] = metav1.Condition{
					Type:               conditionType,
					Status:             status,
					LastTransitionTime: now,
					Reason:             reason,
					Message:            message,
				}
			}
			return conditions
		}
	}
	return append(conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
	})
}
