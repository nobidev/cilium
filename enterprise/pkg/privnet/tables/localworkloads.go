// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tables

import (
	"cmp"
	"strconv"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/time"
)

// LocalWorkload represents a private networks enabled workload running locally.
type LocalWorkload struct {
	// EndpointID is the Cilium's numeric identifier of the endpoint.
	EndpointID uint16

	// Namespace is the Kubernetes namespace this endpoint lives in.
	Namespace string

	// Endpoint contains the identifiers from the pod network point of view.
	Endpoint iso_v1alpha1.PrivateNetworkEndpointSliceEndpoint

	// Interface contains identifiers from the private network point of view.
	Interface iso_v1alpha1.PrivateNetworkEndpointSliceInterface

	// ActivatedAt is the instant in time in which this entry was marked as active.
	ActivatedAt time.Time
}

var _ statedb.TableWritable = &LocalWorkload{}

func (lw *LocalWorkload) TableHeader() []string {
	return []string{
		"Endpoint", "ID",
		"Network", "NetworkIPv4", "NetworkIPv6",
		"PodIPv4", "PodIPv6", "ActivatedAt",
	}
}

func (lw *LocalWorkload) TableRow() []string {
	activatedAt := "<inactive>"
	if !lw.ActivatedAt.IsZero() {
		activatedAt = lw.ActivatedAt.UTC().Format(time.RFC3339)
	}

	return []string{
		lw.Namespace + "/" + lw.Endpoint.Name,
		strconv.FormatUint(uint64(lw.EndpointID), 10),
		lw.Interface.Network,
		cmp.Or(lw.Interface.Addressing.IPv4, "N/A"),
		cmp.Or(lw.Interface.Addressing.IPv6, "N/A"),
		cmp.Or(lw.Endpoint.Addressing.IPv4, "N/A"),
		cmp.Or(lw.Endpoint.Addressing.IPv6, "N/A"),
		activatedAt,
	}
}

var (
	localWorkloadsID = statedb.Index[*LocalWorkload, uint16]{
		Name: "id",
		FromObject: func(obj *LocalWorkload) index.KeySet {
			return index.NewKeySet(index.Uint16(obj.EndpointID))
		},
		FromKey:    index.Uint16,
		FromString: index.Uint16String,
		Unique:     true,
	}

	localWorkloadsNamespace = statedb.Index[*LocalWorkload, string]{
		Name: "namespace",
		FromObject: func(obj *LocalWorkload) index.KeySet {
			return index.NewKeySet(index.String(obj.Namespace))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     false,
	}

	// LocalWorkloadsByID queries the local workloads table by ID.
	LocalWorkloadsByID = localWorkloadsID.Query

	// LocalWorkloadsByNamespace queries the local workloads table by endpoint namespace.
	LocalWorkloadsByNamespace = localWorkloadsNamespace.Query
)

func NewLocalWorkloadsTable(db *statedb.DB) (statedb.RWTable[*LocalWorkload], error) {
	return statedb.NewTable(
		db,
		"privnet-local-workloads",
		localWorkloadsID,
		localWorkloadsNamespace,
	)
}
