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
	"strconv"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/enterprise/pkg/privnet/types"
)

type ExternalEndpoint struct {
	Name      string
	Namespace string

	types.EndpointProperties

	Owner  string
	Status reconciler.Status
}

func ExternalEndpointKey(namespace, name string) string {
	return namespace + "/" + name
}

func (e *ExternalEndpoint) K8sNamespaceAndName() string {
	return ExternalEndpointKey(e.Namespace, e.Name)
}

func (e *ExternalEndpoint) TableHeader() []string {
	return []string{"Namespace", "Name", "Network", "MAC", "IPv4", "IPv6", "Labels", "Owner", "Status"}
}

func (e *ExternalEndpoint) TableRow() []string {
	return []string{
		e.Namespace,
		e.Name,
		e.Network,
		e.MAC.String(),
		e.IPv4.String(),
		e.IPv6.String(),
		strconv.Itoa(len(e.Labels)),
		e.Owner,
		e.Status.String(),
	}
}

var externalEndpointsNameIndex = statedb.Index[*ExternalEndpoint, string]{
	Name: "name",
	FromObject: func(obj *ExternalEndpoint) index.KeySet {
		return index.NewKeySet(index.String(obj.K8sNamespaceAndName()))
	},
	FromString: index.FromString,
	FromKey:    index.String,
	Unique:     true,
}

// ExternalEndpointByName quers the external endpoints table by namespace and name.
func ExternalEndpointByName(namespace, name string) statedb.Query[*ExternalEndpoint] {
	return externalEndpointsNameIndex.Query(ExternalEndpointKey(namespace, name))
}

func NewExternalEndpointsTable(db *statedb.DB) (statedb.RWTable[*ExternalEndpoint], error) {
	return statedb.NewTable(
		db,
		"privnet-external-endpoints",
		externalEndpointsNameIndex,
	)
}
