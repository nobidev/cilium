//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

const (
	// indexDelimiter is the delimiter used to concatenate strings for composite indexes.
	indexDelimiter = "|"
)

type Instance struct {
	Cluster tables.ClusterName
	Name    tables.NodeName
}

func NewInstance(in string) (Instance, error) {
	tokens := strings.Split(in, "/")
	if len(tokens) != 2 {
		return Instance{}, errors.New("cannot parse instance")
	}

	return Instance{
		Cluster: tables.ClusterName(tokens[0]),
		Name:    tables.NodeName(tokens[1]),
	}, nil
}

func NewInstanceFromINBNode(no tables.INBNode) Instance {
	return Instance{Cluster: no.Cluster, Name: no.Name}
}

func (i Instance) String() string {
	return string(i.Cluster) + "/" + string(i.Name)
}

func (i Instance) SocketName() string {
	return fmt.Sprintf("test-health-%s-%s.sock", i.Cluster, i.Name)
}

func (i Instance) ToINBNode() tables.INBNode {
	return tables.INBNode{Cluster: i.Cluster, Name: i.Name}
}

type InstanceNetwork struct {
	Instance Instance
	Network  tables.NetworkName
	Health   tables.INBHealthState
}

func (in InstanceNetwork) TableHeader() []string {
	return []string{"Instance", "Network", "Health"}
}

func (in InstanceNetwork) TableRow() []string {
	return []string{in.Instance.String(), string(in.Network), in.Health.String()}
}

type instanceNetworkKey string

func (key instanceNetworkKey) Key() index.Key {
	return index.String(string(key))
}

func newKeyFromInstance(inst Instance) instanceNetworkKey {
	return instanceNetworkKey(inst.String() + indexDelimiter)
}

func newKey(inst Instance, network tables.NetworkName) instanceNetworkKey {
	return instanceNetworkKey(inst.String()+indexDelimiter) + instanceNetworkKey(network)
}

var (
	instanceNetworkIndex = statedb.Index[InstanceNetwork, instanceNetworkKey]{
		Name: "instance-network",
		FromObject: func(in InstanceNetwork) index.KeySet {
			return index.NewKeySet(newKey(in.Instance, in.Network).Key())
		},
		FromKey:    instanceNetworkKey.Key,
		FromString: index.FromString,
		Unique:     true,
	}
)

func byObject(e InstanceNetwork) statedb.Query[InstanceNetwork] {
	return instanceNetworkIndex.QueryFromObject(e)
}

func byINB(inb Instance) statedb.Query[InstanceNetwork] {
	return instanceNetworkIndex.Query(newKeyFromInstance(inb))
}

func newTable(db *statedb.DB, name string) (statedb.RWTable[InstanceNetwork], error) {
	return statedb.NewTable(db, name, instanceNetworkIndex)
}
