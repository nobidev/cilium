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
	"fmt"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
)

type Instance struct {
	Cluster tables.ClusterName
	Name    tables.NodeName
}

func (i Instance) String() string {
	return string(i.Cluster) + "/" + string(i.Name)
}

func (i Instance) SocketName() string {
	return fmt.Sprintf("test-health-%s-%s.sock", i.Cluster, i.Name)
}
