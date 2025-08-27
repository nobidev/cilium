// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package connectionlog

import (
	typeV1 "github.com/isovalent/ipa/common/k8s/type/v1alpha"
	graphV1 "github.com/isovalent/ipa/graph/v1alpha"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/time"
)

// flowstatToConnection convert a flowstats val into a graphV1 Connection.
func flowstatToConnection(v flowstatval) *graphV1.Connection {
	src, dst := flowToVertices(v)
	if src == nil || dst == nil {
		return nil
	}
	link := flowstatvalEdge(v)
	return &graphV1.Connection{
		Source:      src,
		Destination: dst,
		Links:       []*graphV1.Edge{link},
	}
}

// flowToVertices extract a pair of graphV1 Vertices source and destination
// from a flowstatval.
func flowToVertices(v flowstatval) (src, dst *graphV1.Vertex) {
	// return the empty string when the given slice is empty, or the first
	// element otherwise.
	first := func(xs []string) string {
		if len(xs) == 0 {
			return ""
		}
		return xs[0]
	}

	src = endpointToVertex(
		v.flow.GetSource(),
		v.flow.GetNodeName(),
		v.flow.GetIP().GetSource(),
		first(v.flow.GetSourceNames()),
	)
	dst = endpointToVertex(
		v.flow.GetDestination(),
		v.flow.GetNodeName(),
		v.flow.GetIP().GetDestination(),
		first(v.flow.GetDestinationNames()),
	)
	return
}

// flowstatvalEdge extract a graphV1 Edge from a flowstatval.
func flowstatvalEdge(v flowstatval) *graphV1.Edge {
	return &graphV1.Edge{
		Type: &graphV1.Edge_RoutingTelemetry{
			RoutingTelemetry: &graphV1.EdgeTypeRoutingTelemetry{
				RoutingForwardedTotal:  v.forwarded,
				RoutingDroppedTotal:    v.dropped,
				RoutingErrorTotal:      v.errored,
				RoutingAuditTotal:      v.audited,
				RoutingRedirectedTotal: v.redirected,
				RoutingTracedTotal:     v.traced,
				RoutingTranslatedTotal: v.translated,
			},
		},
	}
}

// may return nil if the given endpoint should be ignored.
func endpointToVertex(ep *flowpb.Endpoint, node, addr, name string) *graphV1.Vertex {
	id := identity.NumericIdentity(ep.GetIdentity())
	// Handle world specifically since it has a dedicated type representation
	// at the in the graphV1 API.
	switch id {
	case identity.ReservedIdentityWorld,
		identity.ReservedIdentityWorldIPv4,
		identity.ReservedIdentityWorldIPv6:
		return &graphV1.Vertex{
			Family: &graphV1.Vertex_WorldEntity{
				// NOTE: no port info, we don't aggregate at that level yet.
				WorldEntity: &graphV1.VertexFamilyWorldEntity{
					DnsName: name,
					Ip:      addr,
				},
			},
		}
	}

	// Initialize a Kubernetes vertex with all the info shared between reserved
	// identites and Pods.
	k8s := &graphV1.VertexFamilyKubernetes{
		// Don't fill in k8s Resource related stuff besides
		// ResourceKind nor NodeName and ContainerName as the info are
		// missing from Hubble flows. endpointManager could provide
		// them but at an additional overhead cost.
		ClusterName: ep.GetClusterName(),
		Namespace:   ep.GetNamespace(),
		PodName:     ep.GetPodName(),
		Ip:          addr,
	}

	// NOTE: world identites have already been handled earlier.
	switch id {
	// TODO: figure out which other reserved identities we wish to handle as
	// exception, if any. If we choose to ignore e.g. ReservedIdentityUnmanaged
	// or else maybe it would make sense to filter them out earlier at the
	// connLogger level.
	case identity.ReservedIdentityHost:
		// the only case where we're sure to know the node name.
		k8s.NodeName = node
	default: // non-reserved identity handling.
		if ep.GetPodName() == "" {
			// Not a Pod, maybe a health-check etc. not filtered by the
			// connLogger. Ignore it since we cannot represent it meaningfully
			// in the graphV1 API.
			// TODO: have some kind of metrics for the ignored vertices?
			return nil
		}
		// NOTE: should we try ep.GetWorkloads() and adapt k8s.WorkloadKind
		// accordingly?
		k8s.WorkloadKind = typeV1.WorkloadKind_WORKLOAD_KIND_POD
		k8s.ResourceKind = typeV1.ResourceKind_RESOURCE_KIND_WORKLOAD
	}

	return &graphV1.Vertex{
		Family: &graphV1.Vertex_Kubernetes{
			Kubernetes: k8s,
		},
	}
}

func connectionLog(from, to time.Time, connections []*graphV1.Connection) *graphV1.ConnectionLog {
	return &graphV1.ConnectionLog{
		Emitter:     graphV1.Emitter_EMITTER_HUBBLE,
		WindowStart: timestamppb.New(from),
		WindowEnd:   timestamppb.New(to),
		Connections: connections,
	}
}
