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
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/cilium/hive/cell"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type ServiceChangeCallback func(clusterName string)

type DisconnectCallback func(clusterName string)

const (
	informerResyncPeriod = 5 * time.Minute
	remoteClusterTimeout = 5 * time.Second
)

type remoteClusterManager struct {
	logger *slog.Logger
	mu     lock.RWMutex

	clusters        map[string]*remoteCluster
	onServiceChange ServiceChangeCallback
	onDisconnect    DisconnectCallback
}

type remoteCluster struct {
	name            string
	client          client.Client
	restConfig      *rest.Config
	cancel          context.CancelFunc
	informerFactory informers.SharedInformerFactory
	informerStop    chan struct{}
}

type remoteClusterManagerParams struct {
	cell.In

	Logger *slog.Logger
	Config Config
}

func newRemoteClusterManager(params remoteClusterManagerParams) *remoteClusterManager {
	return &remoteClusterManager{
		logger:   params.Logger.With(logfields.LogSubsys, "remote-cluster-manager"),
		clusters: make(map[string]*remoteCluster),
	}
}

func (m *remoteClusterManager) SetServiceChangeCallback(cb ServiceChangeCallback) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onServiceChange = cb
}

func (m *remoteClusterManager) SetDisconnectCallback(cb DisconnectCallback) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onDisconnect = cb
}

// EnsureCluster ensures a connection to the remote cluster exists and is valid.
// It also sets up a watch on Services to trigger reconciliation when they change.
func (m *remoteClusterManager) EnsureCluster(
	ctx context.Context,
	cluster *isovalentv1alpha1.LBK8sBackendCluster,
	secret *corev1.Secret,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, exists := m.clusters[cluster.Name]
	if exists {
		if err := m.verifyConnection(ctx, existing); err == nil {
			return nil
		}
		// Connection is no longer valid, close it and return error.
		// The next reconciliation will attempt to reconnect with
		// potentially updated credentials.
		m.logger.Info("remote cluster connection no longer valid",
			logfields.ClusterName, cluster.Name)
		m.stopClusterLocked(existing)
		delete(m.clusters, cluster.Name)
		return fmt.Errorf("remote cluster connection lost")
	}

	restConfig, err := m.buildRestConfig(secret)
	if err != nil {
		return fmt.Errorf("failed to build REST config: %w", err)
	}

	k8sClient, err := client.New(restConfig, client.Options{})
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("failed to create clientset: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)

	informerFactory := informers.NewSharedInformerFactory(clientset, informerResyncPeriod)
	informerStop := make(chan struct{})

	rc := &remoteCluster{
		name:            cluster.Name,
		client:          k8sClient,
		restConfig:      restConfig,
		cancel:          cancel,
		informerFactory: informerFactory,
		informerStop:    informerStop,
	}

	if err := m.verifyConnection(ctx, rc); err != nil {
		cancel()
		return fmt.Errorf("failed to verify connection: %w", err)
	}

	serviceInformer := informerFactory.Core().V1().Services().Informer()
	clusterName := cluster.Name // capture for closure

	_, err = serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			svc, ok := obj.(*corev1.Service)
			if !ok {
				return
			}
			if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
				m.logger.Debug("service added in remote cluster",
					logfields.ClusterName, clusterName,
					logfields.K8sNamespace, svc.Namespace,
					logfields.Name, svc.Name,
				)
				m.triggerReconcile(clusterName)
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			oldSvc, ok1 := oldObj.(*corev1.Service)
			newSvc, ok2 := newObj.(*corev1.Service)
			if !ok1 || !ok2 {
				return
			}
			if oldSvc.Spec.Type == corev1.ServiceTypeLoadBalancer ||
				newSvc.Spec.Type == corev1.ServiceTypeLoadBalancer {
				m.logger.Debug("service updated in remote cluster",
					logfields.ClusterName, clusterName,
					logfields.K8sNamespace, newSvc.Namespace,
					logfields.Name, newSvc.Name,
				)
				m.triggerReconcile(clusterName)
			}
		},
		DeleteFunc: func(obj any) {
			svc, ok := obj.(*corev1.Service)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					return
				}
				svc, ok = tombstone.Obj.(*corev1.Service)
				if !ok {
					return
				}
			}
			if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
				m.logger.Debug("service deleted in remote cluster",
					logfields.ClusterName, clusterName,
					logfields.K8sNamespace, svc.Namespace,
					logfields.Name, svc.Name,
				)
				m.triggerReconcile(clusterName)
			}
		},
	})
	if err != nil {
		cancel()
		return fmt.Errorf("failed to add event handler: %w", err)
	}

	// Also watch nodes for changes (new nodes, removed nodes, IP changes)
	nodeInformer := informerFactory.Core().V1().Nodes().Informer()
	_, err = nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			m.logger.Debug("node added in remote cluster", logfields.ClusterName, clusterName)
			m.triggerReconcile(clusterName)
		},
		UpdateFunc: func(oldObj, newObj any) {
			// Only trigger on IP address changes
			oldNode, ok1 := oldObj.(*corev1.Node)
			newNode, ok2 := newObj.(*corev1.Node)
			if !ok1 || !ok2 {
				return
			}
			if nodeIPChanged(oldNode, newNode) {
				m.logger.Debug("node IP changed in remote cluster", logfields.ClusterName, clusterName)
				m.triggerReconcile(clusterName)
			}
		},
		DeleteFunc: func(obj any) {
			m.logger.Debug("node deleted in remote cluster", logfields.ClusterName, clusterName)
			m.triggerReconcile(clusterName)
		},
	})
	if err != nil {
		cancel()
		return fmt.Errorf("failed to add node event handler: %w", err)
	}

	// Watch error handlers must be set before starting the informers.
	watchErrorHandler := func(r *cache.Reflector, err error) {
		m.logger.Warn("watch error on remote cluster",
			logfields.ClusterName, clusterName,
			logfields.Error, err,
		)
		m.triggerDisconnect(clusterName)
	}

	if err := serviceInformer.SetWatchErrorHandler(watchErrorHandler); err != nil {
		cancel()
		return fmt.Errorf("failed to set service watch error handler: %w", err)
	}
	if err := nodeInformer.SetWatchErrorHandler(watchErrorHandler); err != nil {
		cancel()
		return fmt.Errorf("failed to set node watch error handler: %w", err)
	}

	informerFactory.Start(informerStop)

	m.logger.Info("waiting for informer cache sync", logfields.ClusterName, cluster.Name)
	if !cache.WaitForCacheSync(informerStop, serviceInformer.HasSynced, nodeInformer.HasSynced) {
		cancel()
		close(informerStop)
		return fmt.Errorf("failed to sync informer cache")
	}

	m.clusters[cluster.Name] = rc
	m.logger.Info("established connection to remote cluster with watches",
		logfields.ClusterName, cluster.Name)

	return nil
}

func (m *remoteClusterManager) triggerReconcile(clusterName string) {
	m.mu.RLock()
	cb := m.onServiceChange
	m.mu.RUnlock()

	if cb != nil {
		cb(clusterName)
	}
}

func (m *remoteClusterManager) triggerDisconnect(clusterName string) {
	m.mu.Lock()
	cb := m.onDisconnect
	// Remove the cluster from the map so the next reconcile will try to reconnect
	if _, exists := m.clusters[clusterName]; exists {
		if rc, ok := m.clusters[clusterName]; ok {
			m.stopClusterLocked(rc)
		}
		delete(m.clusters, clusterName)
	}
	m.mu.Unlock()

	if cb != nil {
		cb(clusterName)
	}
}

func nodeIPChanged(oldNode, newNode *corev1.Node) bool {
	getInternalIPs := func(node *corev1.Node) []string {
		var ips []string
		for _, addr := range node.Status.Addresses {
			if addr.Type == corev1.NodeInternalIP {
				ips = append(ips, addr.Address)
			}
		}
		slices.Sort(ips)
		return ips
	}
	return !slices.Equal(getInternalIPs(oldNode), getInternalIPs(newNode))
}

func (m *remoteClusterManager) GetClient(clusterName string) (client.Client, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rc, exists := m.clusters[clusterName]
	if !exists {
		return nil, fmt.Errorf("cluster %q not found", clusterName)
	}

	return rc.client, nil
}

func (m *remoteClusterManager) Stop(clusterName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rc, exists := m.clusters[clusterName]
	if exists {
		m.stopClusterLocked(rc)
		delete(m.clusters, clusterName)
	}
}

func (m *remoteClusterManager) StopAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, rc := range m.clusters {
		m.stopClusterLocked(rc)
	}
	m.clusters = make(map[string]*remoteCluster)

	return nil
}

// Must be called with lock held.
func (m *remoteClusterManager) stopClusterLocked(rc *remoteCluster) {
	m.logger.Info("stopping remote cluster connection", logfields.ClusterName, rc.name)

	if rc.informerStop != nil {
		close(rc.informerStop)
	}

	if rc.cancel != nil {
		rc.cancel()
	}
}

func (m *remoteClusterManager) buildRestConfig(
	secret *corev1.Secret,
) (*rest.Config, error) {
	kubeconfig, ok := secret.Data["kubeconfig"]
	if !ok {
		return nil, fmt.Errorf("secret must contain 'kubeconfig' key")
	}

	config, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse kubeconfig: %w", err)
	}
	config.Timeout = remoteClusterTimeout
	return config, nil
}

func (m *remoteClusterManager) verifyConnection(ctx context.Context, rc *remoteCluster) error {
	ctx, cancel := context.WithTimeout(ctx, remoteClusterTimeout)
	defer cancel()

	var nsList corev1.NamespaceList
	if err := rc.client.List(ctx, &nsList, client.Limit(1)); err != nil {
		return fmt.Errorf("failed to list namespaces: %w", err)
	}
	return nil
}
