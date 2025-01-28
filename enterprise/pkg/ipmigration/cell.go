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
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	log "github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	endpointrestapi "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	ipamrestapi "github.com/cilium/cilium/api/v1/server/restapi/ipam"
	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/pkg/ipmigration/types"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/ipam"
	ipamMetadata "github.com/cilium/cilium/pkg/ipam/metadata"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/time"
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

	EndpointTemplates *endpointTemplates

	IPAMMetadataManager ipamMetadata.Manager
	LocalNodeStore      *node.LocalNodeStore

	JobGroup job.Group
	Log      *slog.Logger
}

var defaultConfig = types.Config{
	EnablePodIPMigration: false,
}

type cfg struct {
	ipv4Enabled bool
	ipv6Enabled bool

	retryDuration time.Duration
	retryAttempts int
}

// manager attached and detaches pods.
//   - handlePostIPAM + handlePutEndpointID: These functions intercept the API calls issued by cilium-cni during CNI ADD.
//     They are responsible for mocking IPAM allocation and endpoint creation if they see that CNI ADD request is for a
//     detached pod. All other requests are forwarded to the upstream handlers in Daemon.
type manager struct {
	log *slog.Logger
	cfg cfg

	endpointTemplates *endpointTemplates

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
		endpointTemplates: params.EndpointTemplates,

		localNodeStore:      params.LocalNodeStore,
		ipamMetadataManager: params.IPAMMetadataManager,

		db:       params.StateDB,
		podTable: params.PodTable,
	}

	return m
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
				slog.String("pod", podNamespace+"/"+podName))
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
		slog.String("pod", p.Endpoint.K8sNamespace+"/"+p.Endpoint.K8sPodName),
		slog.String("uid", p.Endpoint.K8sUID))

	// Check if pod has detached annotation
	pod, err := m.fetchPod(p.HTTPRequest.Context(), p.Endpoint.K8sNamespace, p.Endpoint.K8sPodName, p.Endpoint.K8sUID)
	if err != nil {
		log.Warn("Failed to obtain pod object from K8s API",
			slog.Any("err", err))
		return api.Error(endpointrestapi.PutEndpointIDFailedCode, err)
	}

	// Migration logic can only be used when an endpoint is created for a pod with a K8s UID
	if len(p.Endpoint.K8sUID) > 0 {
		err := m.endpointTemplates.persistEndpointTemplate(p.Endpoint)
		if err != nil {
			log.Error("Failed to persist endpoint template. Any IP migration to this pod will not be able to succeed",
				slog.Any("err", err))
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
				slog.String("pod", podNamespace+"/"+podName),
				slog.Any("err", err))
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
