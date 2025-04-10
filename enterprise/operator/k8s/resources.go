//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package k8s

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/k8s"
)

var (
	// ResourcesCell provides a set of handles to Kubernetes resources used throughout the
	// operator. Each of the resources share a client-go informer and backing store so we only
	// have one watch API call for each resource kind and that we maintain only one copy of each object.
	//
	// See pkg/k8s/resource/resource.go for documentation on the Resource[T] type.
	ResourcesCell = cell.Module(
		"isovalent-k8s-resources",
		"Isovalent Operator Kubernetes resources",

		cell.Provide(
			k8s.IsovalentNetworkPolicyResource,
			k8s.IsovalentClusterwideNetworkPolicyResource,
		),
	)
)
