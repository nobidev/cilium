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
	"fmt"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

// EndpointSlice represents a Kubernetes PrivateNetworkEndpointSlice
type EndpointSlice struct {
	// Namespace of the slice. We currently assume a single local slice per namespace, so this is also the primary key
	Namespace string

	// Slice contains the actual slice - may be nil if the slice has not yet been created
	Slice *iso_v1alpha1.PrivateNetworkEndpointSlice

	// Status contains the publishing status of this endpoint slice
	Status reconciler.Status
}

var _ statedb.TableWritable = EndpointSlice{}

func (es EndpointSlice) TableHeader() []string {
	return []string{
		"Namespace",
		"Slice",
		"Endpoints",
		"Status",
	}
}

func (es EndpointSlice) TableRow() []string {
	slice := "N/A"
	endpoints := "N/A"
	if es.Slice != nil {
		slice = es.Slice.Name
		endpoints = fmt.Sprintf("%d", len(es.Slice.Endpoints))
	}

	return []string{
		es.Namespace,
		slice,
		endpoints,
		es.Status.String(),
	}
}

// EndpointSlicesByNamespace queries the endpoint slices table by namespace.
func EndpointSlicesByNamespace(namespace string) statedb.Query[EndpointSlice] {
	return endpointSlicesByNamespace.Query(namespace)
}

var (
	endpointSlicesByNamespace = statedb.Index[EndpointSlice, string]{
		Name: "namespace",
		FromObject: func(obj EndpointSlice) index.KeySet {
			return index.NewKeySet(index.String(obj.Namespace))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}
)

func NewEndpointSlicesTable(db *statedb.DB) (statedb.RWTable[EndpointSlice], error) {
	return statedb.NewTable(
		db,
		"privnet-local-endpointslices",
		endpointSlicesByNamespace,
	)
}
