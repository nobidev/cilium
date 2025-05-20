//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

// Package ipmigration is responsible for supporting IP migration by allowing pods to be attached and detached from Cilium.
// A detached pod is a pod is a pod without a corresponding Cilium endpoint (and without connectivity), but allows the IP
// to be used concurrently by a different pod. This is useful in the context of KubeVirt VM migration where the target
// VM can be set up in a detached state, and become attached once migration has finished the source VM pod has been deleted,
// thereby also allowing ownership of the source VM pod IP to be transferred to the target pod.
package ipmigration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	log "github.com/sirupsen/logrus"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/api/v1/models"
	endpointrestapi "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	ipamrestapi "github.com/cilium/cilium/api/v1/server/restapi/ipam"
	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/pkg/ipmigration/types"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointapi "github.com/cilium/cilium/pkg/endpoint/api"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/ipam"
	ipamMetadata "github.com/cilium/cilium/pkg/ipam/metadata"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/time"
)

const (
	logfieldPruned = "pruned"
)

var Cell = cell.Module(
	"ip-migration",
	"Pod IP migration support cell",

	cell.Config(defaultConfig),

	cell.Provide(newMigrationManager),
	cell.ProvidePrivate(persistentEndpointTemplates),
	cell.DecorateAll(injectAPIHandlers),
)

type managerParams struct {
	cell.In

	Config       types.Config
	DaemonConfig *option.DaemonConfig

	StateDB  *statedb.DB
	PodTable statedb.Table[agentK8s.LocalPod]

	RestorerPromise promise.Promise[endpointstate.Restorer]

	EndpointManager    endpointmanager.EndpointManager
	EndpointTemplates  *endpointTemplates
	EndpointAPIManager endpointapi.EndpointAPIManager

	IPAM                *ipam.IPAM
	IPAMMetadataManager ipamMetadata.Manager
	LocalNodeStore      *node.LocalNodeStore

	JobGroup job.Group
	Log      *slog.Logger
}

var defaultConfig = types.Config{
	EnablePodIPMigration: false,
}

type ipamAllocator interface {
	AllocateIP(ip net.IP, owner string, pool ipam.Pool) error
	ReleaseIP(ip net.IP, pool ipam.Pool) error
}

type endpointManager interface {
	GetEndpointsByPodName(name string) []*endpoint.Endpoint
	RemoveEndpoint(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) []error
}

type endpointAPIManager interface {
	CreateEndpoint(ctx context.Context, epTemplate *models.EndpointChangeRequest) (*endpoint.Endpoint, int, error)
}

type cfg struct {
	ipv4Enabled bool
	ipv6Enabled bool

	retryDuration time.Duration
	retryAttempts int
}

// manager attached and detaches pods. It has two entry points:
//   - handlePostIPAM + handlePutEndpointID: These functions intercept the API calls issued by cilium-cni during CNI ADD.
//     They are responsible for mocking IPAM allocation and endpoint creation if they see that CNI ADD request is for a
//     detached pod. All other requests are forwarded to the upstream handlers in Daemon.
//   - handlePodEvent: This function is called on local pod updates. If it observes the removal of the `detached`
//     annotation from a pod, it will attempt to attach this pod by creating the endpoint(s) for it based on the parameters
//     intercepted in the earlier handlePutEndpointID call. If it sees the `detached` annotation being added to a pod,
//     it will detach that pod by removing all associated endpoints for that pod.
type manager struct {
	log *slog.Logger
	cfg cfg

	endpointManager    endpointManager
	endpointTemplates  *endpointTemplates
	endpointAPIManager endpointAPIManager

	ipam                ipamAllocator
	ipamMetadataManager ipamMetadata.Manager
	localNodeStore      *node.LocalNodeStore

	db       *statedb.DB
	podTable statedb.Table[agentK8s.LocalPod]

	// Note: These two fields are set by injectAPIHandlers during Hive construction
	putEP     endpointrestapi.PutEndpointIDHandler
	ipamAlloc ipamrestapi.PostIpamHandler
}

// newMigrationManager creates a new ipmigration manager.
func newMigrationManager(params managerParams) *manager {
	if !params.Config.EnablePodIPMigration {
		return nil
	}

	m := &manager{
		log: params.Log,
		cfg: cfg{
			ipv4Enabled: params.DaemonConfig.EnableIPv4,
			ipv6Enabled: params.DaemonConfig.EnableIPv6,

			retryDuration: 100 * time.Millisecond,
			retryAttempts: 20,
		},

		endpointManager:    params.EndpointManager,
		endpointTemplates:  params.EndpointTemplates,
		endpointAPIManager: params.EndpointAPIManager,

		ipam:                params.IPAM,
		ipamMetadataManager: params.IPAMMetadataManager,
		localNodeStore:      params.LocalNodeStore,

		db:       params.StateDB,
		podTable: params.PodTable,
	}

	// The pod watcher can only be started once all endpoints have been restored, as otherwise
	// we observe pods without endpoints, which causes the code to wrongly assume those pods are detached.
	params.JobGroup.Add(
		job.OneShot("start-ip-migration", func(ctx context.Context, _ cell.Health) error {
			// WaitForEndpointRestore blocks until all endpoints have been restored
			restorer, err := params.RestorerPromise.Await(ctx)
			if err != nil {
				return err
			}
			restorer.WaitForEndpointRestore(ctx)

			podStream := resource.NewTableEventStream(params.StateDB, params.PodTable, func(key resource.Key) statedb.Query[agentK8s.LocalPod] {
				return agentK8s.PodByName(key.Namespace, key.Name)
			})

			// Start the pod watcher only once the above statements have unblocked
			params.JobGroup.Add(job.Observer(
				"ip-migration-pod-watcher",
				func(ctx context.Context, event resource.Event[agentK8s.LocalPod]) error {
					err := m.handlePodEvent(ctx, event)
					if err != nil {
						// The IPAM pool not being available is an expected error, thus only log it with level info.
						level := slog.LevelWarn
						if strings.Contains(err.Error(), "pool not (yet) available") {
							level = slog.LevelInfo
						}
						m.log.Log(ctx, level, "Failed to handle pod event, will re-try later",
							logfields.Error, err)
					}
					event.Done(err)
					return nil
				},
				podStream,
			))

			return nil
		}),
	)

	return m
}

// endpointsForPod queries the endpoint manager for a list of endpoints associated with the provided pod.
func (m *manager) endpointsForPod(pod *slim_corev1.Pod) []*endpoint.Endpoint {
	podNSName := k8sUtils.GetObjNamespaceName(&pod.ObjectMeta)
	candidates := m.endpointManager.GetEndpointsByPodName(podNSName)
	endpoints := make([]*endpoint.Endpoint, 0, len(candidates))
	for _, ep := range candidates {
		if ep.K8sUID == string(pod.UID) {
			endpoints = append(endpoints, ep)
		}
	}

	return endpoints
}

// detachRunningPod detaches a running pod by removing all endpoints
func (m *manager) detachRunningPod(pod resource.Key, endpoints []*endpoint.Endpoint) error {
	m.log.Info("Detaching pod endpoints",
		logfields.Pod, pod)

	var err error
	deleteConfig := endpoint.DeleteConfig{}
	for _, ep := range endpoints {
		err = errors.Join(err, errors.Join(m.endpointManager.RemoveEndpoint(ep, deleteConfig)...))
	}
	return err
}

// createEndpoint creates a new endpoint based on the provided EndpointChangeRequest ep.
// Before it creates the endpoint, it will allocate the endpoint's IPs using the IPAM subsystem.
func (m *manager) createEndpoint(
	ctx context.Context,
	ep *models.EndpointChangeRequest,
) (err error) {
	owner := ep.K8sNamespace + "/" + ep.K8sPodName

	// Allocate IPv4 address
	if addr := ep.Addressing; addr != nil && addr.IPV4 != "" {
		ip := net.ParseIP(addr.IPV4)
		pool := ipam.Pool(addr.IPV4PoolName)
		if ip == nil {
			return fmt.Errorf("invalid ipv4 address: %s", addr.IPV4)
		}

		err = m.ipam.AllocateIP(ip, owner, pool)
		if err != nil {
			return fmt.Errorf("ipv4 address allocation: %w", err)
		}
		defer func() {
			if err != nil {
				m.ipam.ReleaseIP(ip, pool)
			}
		}()
	}

	// Allocate IPv6 address
	if addr := ep.Addressing; addr != nil && addr.IPV6 != "" {
		ip := net.ParseIP(addr.IPV6)
		pool := ipam.Pool(addr.IPV6PoolName)
		if ip == nil {
			return fmt.Errorf("invalid ipv6 address: %s", addr.IPV6)
		}

		err = m.ipam.AllocateIP(ip, owner, pool)
		if err != nil {
			return fmt.Errorf("ipv6 address allocation: %w", err)
		}
		defer func() {
			if err != nil {
				m.ipam.ReleaseIP(ip, pool)
			}
		}()
	}

	_, _, err = m.endpointAPIManager.CreateEndpoint(ctx, ep)
	return err
}

// attachRunningPod attaches the specified pod by obtaining its endpoint template and creating a new endpoint
// for each found template
func (m *manager) attachRunningPod(ctx context.Context, pod *slim_corev1.Pod) error {
	epTemplates, err := m.endpointTemplates.getEndpointTemplatesForPod(pod.UID)
	if err != nil {
		return fmt.Errorf("failed to attach pod %s: %w", pod.Namespace+"/"+pod.Name, err)
	}

	for _, ep := range epTemplates {
		err = errors.Join(err, m.createEndpoint(ctx, ep))
	}

	if err == nil {
		m.log.Info("Attached pod endpoints",
			logfields.Pod, pod.Namespace+"/"+pod.Name,
			logfields.Endpoints, len(epTemplates))
	}

	return err
}

// collectPodUIDs returns a set of all pod UIDs found in the manager's pod store
func (m *manager) collectPodUIDs() (sets.Set[k8sTypes.UID], error) {
	uids := make(sets.Set[k8sTypes.UID])
	for pod := range m.podTable.All(m.db.ReadTxn()) {
		uids.Insert(pod.UID)
	}

	return uids, nil
}

// handlePodEvent is responsible for attaching and detaching pods based on annotation changes:
// - For a pod upsert event, it checks the pod's annotations and attaches or detaches the pod accordingly
// - For a pod delete event, it cleans up the pods' endpoint templates
// - Fod a pod sync event, it cleans up all endpoint templates for pods no longer found in the pod store
func (m *manager) handlePodEvent(ctx context.Context, event resource.Event[agentK8s.LocalPod]) error {
	pod := event.Object
	switch event.Kind {
	case resource.Upsert:
		// Skip pod objects without a UID
		if len(pod.UID) == 0 {
			m.log.Warn("Pod event received with empty UID, ignoring",
				logfields.Pod, event.Key)
			return nil
		}

		// Skip pods which are not running, as they might be in the process of being created
		if pod.Status.Phase != slim_corev1.PodRunning {
			return nil
		}
		// Skip pods not managed by Cilium
		if pod.Spec.HostNetwork {
			return nil
		}

		_, hasDetachAnnotation := pod.Annotations[types.DetachedAnnotation]
		endpoints := m.endpointsForPod(pod.Pod)

		switch {
		case hasDetachAnnotation && len(endpoints) > 0:
			return m.detachRunningPod(event.Key, endpoints)
		case !hasDetachAnnotation && len(endpoints) == 0:
			return m.attachRunningPod(ctx, pod.Pod)
		}
	case resource.Delete:
		err := m.endpointTemplates.deleteEndpointTemplatesForPod(pod.UID)
		if errors.Is(err, fs.ErrNotExist) {
			return nil // Not returning an error if the endpoint template does not exist
		}
		return err
	case resource.Sync:
		alivePodsUIDs, err := m.collectPodUIDs()
		if err != nil {
			return fmt.Errorf("failed to collect pod UIDs for pruning: %w", err)
		}
		pruned, err := m.endpointTemplates.pruneEndpointTemplates(alivePodsUIDs)
		if err == nil {
			m.log.Debug("Pruned endpoint templates",
				logfieldPruned, pruned)
		} else {
			m.log.Warn("Errors while pruning endpoint templates",
				logfieldPruned, pruned,
				logfields.Error, err)
		}
		// Not returning an error to the caller here, since we do not expect a retry to be ever be successful
		return nil
	}

	return nil
}

// fetchPod returns the pod object from the pod store. If the podUID is provided, then the UID of the fetched pod is
// required to match. If no pod is found in the pod store, it retries to wait for the pod for up to 2 seconds.
func (m *manager) fetchPod(ctx context.Context, podNamespace, podName, podUID string) (pod *slim_corev1.Pod, err error) {
	if podNamespace == "" || podName == "" {
		return nil, nil
	}

	err = resiliency.Retry(ctx, m.cfg.retryDuration, m.cfg.retryAttempts, func(ctx context.Context, retries int) (bool, error) {
		localPod, _, exists := m.podTable.Get(m.db.ReadTxn(), agentK8s.PodByName(podNamespace, podName))
		if !exists {
			return false, nil
		}

		// if podUID is provided, we want to ensure that we are using the correct pod
		if podUID != "" && string(localPod.UID) != podUID {
			m.log.Warn("Detected outdated pod store, retrying",
				logfields.Pod, podNamespace+"/"+podName)
			return false, nil
		}

		pod = localPod.Pod
		return true, nil
	})
	if err != nil {
		return nil, err
	}

	return pod, err
}

// detachedEPModel returns a fake endpoint model for the given endpoint creation request
func (m *manager) detachedEPModel(ep *models.EndpointChangeRequest, pod *slim_corev1.Pod) *models.Endpoint {
	epModel := &models.Endpoint{
		Status: &models.EndpointStatus{
			Networking: &models.EndpointNetworking{
				Addressing:             []*models.AddressPair{ep.Addressing},
				ContainerInterfaceName: ep.ContainerInterfaceName,
				HostMac:                ep.HostMac,
				InterfaceIndex:         ep.InterfaceIndex,
				InterfaceName:          ep.InterfaceName,
				Mac:                    ep.Mac,
			},
			State: models.EndpointStateDisconnected.Pointer(),
		},
	}

	if hwAddr, ok := pod.Annotations[annotation.PodAnnotationMAC]; ok && !ep.DisableLegacyIdentifiers {
		epModel.Status.Networking.Mac = hwAddr
	}

	return epModel
}

// handlePutEndpointID handles `PUT /endpoint/{id}` API calls. If the endpoint creation request is for a pod with a
// detached annotation, it will skip endpoint creation and return a fake endpoint model instead.
// If the endpoint creation request is not for a pod or for an attached pod, it will invoke the upstream handler to
// create the endpoint regularly.
func (m *manager) handlePutEndpointID(p endpointrestapi.PutEndpointIDParams) middleware.Responder {
	log := m.log.With(
		logfields.Pod, p.Endpoint.K8sNamespace+"/"+p.Endpoint.K8sPodName,
		logfields.K8sUID, p.Endpoint.K8sUID)

	// Check if pod has detached annotation
	pod, err := m.fetchPod(p.HTTPRequest.Context(), p.Endpoint.K8sNamespace, p.Endpoint.K8sPodName, p.Endpoint.K8sUID)
	if err != nil {
		log.Warn("Failed to obtain pod object from K8s API",
			logfields.Error, err)
		return api.Error(endpointrestapi.PutEndpointIDFailedCode, err)
	}

	// Migration logic can only be used when an endpoint is created for a pod with a K8s UID
	if len(p.Endpoint.K8sUID) > 0 {
		err := m.endpointTemplates.persistEndpointTemplate(p.Endpoint)
		if err != nil {
			log.Error("Failed to persist endpoint template. Any IP migration to this pod will not be able to succeed",
				logfields.Error, err)
			// We're continuing regardless of this error, since it only matters to pods that need to be migrated
		}

		// If the pod is being created in detached state, do not forward
		// the endpoint creation request and instead return a fake endpoint
		// here
		_, isDetached := pod.Annotations[types.DetachedAnnotation]
		if isDetached {
			return endpointrestapi.
				NewPutEndpointIDCreated().
				WithPayload(m.detachedEPModel(p.Endpoint, pod))
		}
	}

	return m.putEP.Handle(p)
}

// detachedIPAMResponse returns a fake IPAM response based on the contents of the detached pod annotation (detachedIPAMStr)
func (m *manager) detachedIPAMResponse(ctx context.Context, detachedIPAMStr, family, owner, genericPool string) (*models.IPAMResponse, error) {
	ipPair := types.DetachedIpamAddressPair{}
	err := json.Unmarshal([]byte(detachedIPAMStr), &ipPair)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling %q annotation of pod %s: %w", types.DetachedAnnotation, owner, err)
	}

	localNode, err := m.localNodeStore.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("error obtaining local node information: %w", err)
	}

	resp := &models.IPAMResponse{
		HostAddressing: &models.NodeAddressing{},
		Address:        &models.AddressPair{},
	}

	// Extract IPv4 address from detached annotation
	if m.cfg.ipv4Enabled && (family == "ipv4" || family == "") {
		ipv4Pool := genericPool
		if ipv4Pool == "" {
			ipv4Pool, err = m.ipamMetadataManager.GetIPPoolForPod(owner, ipam.IPv4)
			if err != nil {
				return nil, fmt.Errorf("unable to determine IP pool for detached pod %s: %w", owner, err)
			}
		}

		resp.Address.IPV4 = ipPair.IPV4.String()
		resp.Address.IPV4PoolName = ipv4Pool
		resp.IPV4 = &models.IPAMAddressResponse{
			IP: ipPair.IPV4.String(),
		}

		resp.HostAddressing.IPV4 = &models.NodeAddressingElement{
			Enabled:    true,
			IP:         localNode.GetCiliumInternalIP(false).String(),
			AllocRange: localNode.IPv4AllocCIDR.String(),
		}
	}

	// Extract IPv6 address from detached annotation
	if m.cfg.ipv6Enabled && (family == "ipv6" || family == "") {
		ipv6Pool := genericPool

		if ipv6Pool == "" {
			ipv6Pool, err = m.ipamMetadataManager.GetIPPoolForPod(owner, ipam.IPv6)
			if err != nil {
				return nil, fmt.Errorf("unable to determine IP pool for detached pod %s: %w", owner, err)
			}
		}

		resp.Address.IPV6 = ipPair.IPV6.String()
		resp.Address.IPV6PoolName = ipv6Pool
		resp.IPV6 = &models.IPAMAddressResponse{
			IP: ipPair.IPV6.String(),
		}

		resp.HostAddressing.IPV6 = &models.NodeAddressingElement{
			Enabled:    true,
			IP:         localNode.GetCiliumInternalIP(true).String(),
			AllocRange: localNode.IPv6AllocCIDR.String(),
		}
	}

	return resp, nil
}

// handlePostIPAM handles `POST /ipam` API calls. If the endpoint creation request is for a pod with a
// detached annotation, it will skip IPAM allocation return a fake IPAM response based on the pod's annotation instead.
// If the IPAM request is for an attached pod (or not pod at all), then the request is forwarded to the upstream API handler.
func (m *manager) handlePostIPAM(p ipamrestapi.PostIpamParams) middleware.Responder {
	ctx := p.HTTPRequest.Context()
	podNamespace, podName, isQualified := strings.Cut(swag.StringValue(p.Owner), "/")
	if isQualified {
		pod, err := m.fetchPod(ctx, podNamespace, podName, "")
		if err != nil {
			log.Warn("Failed to obtain pod object from K8s API",
				logfields.Pod, podNamespace+"/"+podName,
				logfields.Error, err)
			return api.Error(ipamrestapi.PostIpamFailureCode, err)
		}

		// Check if pod has detached annotation. If so, generate response from annotation
		detachedIPAM, isDetached := pod.Annotations[types.DetachedAnnotation]
		if isDetached {
			family := strings.ToLower(swag.StringValue(p.Family))
			owner := swag.StringValue(p.Owner)
			pool := swag.StringValue(p.Pool)

			resp, err := m.detachedIPAMResponse(ctx, detachedIPAM, family, owner, pool)
			if err != nil {
				return api.Error(ipamrestapi.PostIpamFailureCode, err)
			}
			return ipamrestapi.NewPostIpamCreated().WithPayload(resp)
		}
	}

	// Forward IPAM request if it is not for a pod or the pod is not detached
	return m.ipamAlloc.Handle(p)
}
