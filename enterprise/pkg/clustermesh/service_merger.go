//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package clustermesh

import (
	"log/slog"

	cmcfg "github.com/cilium/cilium/enterprise/pkg/clustermesh/config"
	"github.com/cilium/cilium/pkg/annotation"
	cm "github.com/cilium/cilium/pkg/clustermesh"
	serviceStore "github.com/cilium/cilium/pkg/clustermesh/store"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/source"
)

// ceServiceMerger implements the MergeExternal* methods, overriding the default
// implementation to support additional enterprise features (e.g. phantom services).
type ceServiceMerger struct {
	log    *slog.Logger
	cmcfg  cmcfg.Config
	writer *writer.Writer
}

func injectCEServiceMerger(log *slog.Logger, sc k8s.ServiceCache, clustermesh *cm.ClusterMesh, lbcfg loadbalancer.Config, cmcfg cmcfg.Config, writer *writer.Writer) {
	if clustermesh == nil {
		return
	}

	if !lbcfg.EnableExperimentalLB {
		sm := k8s.NewCEServiceMerger(log, sc, cmcfg)
		cm.InjectCEServiceMerger(clustermesh, sm)
		return
	}

	cesm := &ceServiceMerger{
		log:    log,
		cmcfg:  cmcfg,
		writer: writer,
	}
	cm.InjectCEServiceMerger(clustermesh, cesm)
}

// MergeExternalServiceUpdate merges the update of a cluster service.
func (sm *ceServiceMerger) MergeExternalServiceUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	if sm.cmcfg.EnableClusterAwareAddressing {
		service = annotateBackendsWithID(*service)
	}

	// With phantom services, we'll import the phantom service into ServiceCache.
	// Phantom services must be identified with Cluster + Name + Namespace.
	// Otherwise, naming collision is possible if they exist in multiple clusters.
	globalName := loadbalancer.ServiceName{Cluster: service.Cluster, Name: service.Name, Namespace: service.Namespace}
	localName := loadbalancer.ServiceName{Name: service.Name, Namespace: service.Namespace}

	txn := sm.writer.WriteTxn()
	defer txn.Commit()

	if isPhantomService(service) {
		// Remove any possible endpoints associated with the corresponding local
		// service, to correctly handle the transition to phantom.
		sm.writer.DeleteBackendsOfServiceFromCluster(txn, localName, source.ClusterMesh, service.ClusterID)

		if sm.cmcfg.EnablePhantomServices {
			// Create or update the phantom service.
			svc, fes := clusterServiceToServiceAndFrontends(sm.cmcfg, service)
			if err := sm.writer.UpsertServiceAndFrontends(txn, svc, fes...); err != nil {
				sm.log.Error("Failed to upsert service and frontends",
					logfields.Error, err,
					logfields.ServiceName, svc.Name)
			}

			bes := cm.ClusterServiceToBackendParams(service)
			if err := sm.writer.SetBackendsOfCluster(txn, svc.Name, source.ClusterMesh, service.ClusterID, bes...); err != nil {
				sm.log.Error("Failed to set backends",
					logfields.Error, err,
					logfields.ServiceName, svc.Name)
			}
		}

		return
	}

	// The service was not a phantom service, but it could have been at some point.
	// See if we find an old one and delete it.
	_, _, globalFound := sm.writer.Services().Get(txn, loadbalancer.ServiceByName(globalName))
	if globalFound {
		sm.writer.DeleteBackendsOfServiceFromCluster(txn, globalName, source.ClusterMesh, service.ClusterID)
		sm.writer.DeleteServiceAndFrontends(txn, globalName)
	}

	// Finally update the non-phantom backends
	sm.writer.SetBackendsOfCluster(
		txn,
		localName,
		source.ClusterMesh,
		service.ClusterID,
		cm.ClusterServiceToBackendParams(service)...,
	)
}

// MergeExternalServiceDelete merges the deletion of a cluster service.
func (sm *ceServiceMerger) MergeExternalServiceDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	txn := sm.writer.WriteTxn()
	defer txn.Commit()

	globalName := loadbalancer.ServiceName{Cluster: service.Cluster, Name: service.Name, Namespace: service.Namespace}
	_, _, globalFound := sm.writer.Services().Get(txn, loadbalancer.ServiceByName(globalName))
	if globalFound {
		// A service previously marked as phantom is no longer so, hence it is treated as if it had been deleted.
		sm.writer.DeleteBackendsOfServiceFromCluster(txn, globalName, source.ClusterMesh, service.ClusterID)
		sm.writer.DeleteServiceAndFrontends(txn, globalName)
	}

	localName := loadbalancer.ServiceName{Namespace: service.Namespace, Name: service.Name}
	sm.writer.DeleteBackendsOfServiceFromCluster(
		txn,
		localName,
		source.ClusterMesh,
		service.ClusterID,
	)
}

// annotateBackendsWithID annotates each backend of the service with the
// associated cluster ID, so that it can then be parsed and eventually
// propagated to the datapath for Overlapping PodCIDR support.
//
// The service object is passed by value to create a shallow copy, and
// avoid mutating the original one during this operation.
func annotateBackendsWithID(service serviceStore.ClusterService) *serviceStore.ClusterService {
	backends := make(map[string]serviceStore.PortConfiguration, len(service.Backends))

	for backend, value := range service.Backends {
		backends[cmtypes.AnnotateIPCacheKeyWithClusterID(backend, service.ClusterID)] = value
	}

	service.Backends = backends
	return &service
}

func isPhantomService(s *serviceStore.ClusterService) bool {
	return !s.IncludeExternal && s.Shared
}

func clusterServiceToServiceAndFrontends(cmcfg cmcfg.Config, csvc *serviceStore.ClusterService) (*loadbalancer.Service, []loadbalancer.FrontendParams) {
	name := loadbalancer.ServiceName{
		Name:      csvc.Name,
		Namespace: csvc.Namespace,
		Cluster:   csvc.Cluster,
	}
	svc := &loadbalancer.Service{
		Name:   name,
		Source: source.ClusterMesh,
		Labels: labels.Map2Labels(csvc.Labels, string(source.ClusterMesh)),
		Annotations: map[string]string{
			// Set the global service annnotation to instruct the [clustermesh.ClusterMeshSelectBackends] to
			// include the remote backends.
			annotation.GlobalService: "true",
		},
		Selector:         csvc.Selector,
		NatPolicy:        loadbalancer.SVCNatPolicyNone,
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
	}

	fes := make([]loadbalancer.FrontendParams, 0, len(csvc.Frontends))
	for ipStr, ports := range csvc.Frontends {
		addrCluster, err := cmtypes.ParseAddrCluster(ipStr)
		if err != nil {
			continue
		}
		for portName, port := range ports {
			l4 := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
			portName := loadbalancer.FEPortName(portName)
			fes = append(fes,
				loadbalancer.FrontendParams{
					Address: loadbalancer.L3n4Addr{
						AddrCluster: addrCluster,
						L4Addr:      *l4,
					},
					Type:        loadbalancer.SVCTypeClusterIP,
					ServiceName: name,
					PortName:    portName,
					ServicePort: l4.Port,
				},
			)
		}
	}
	return svc, fes
}
