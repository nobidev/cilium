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

import "github.com/cilium/hive/cell"

var (
	// ResourcesCell provides a set of handles to Kubernetes resources used throughout the
	// enterprise clustermesh-apiserver.
	ResourcesCell = cell.Module(
		"enterprise-k8s-resources",
		"Enterprise clustermesh-apiserver Kubernetes resources",

		cell.Provide(
			PrivateNetworkEndpointSliceResource,
		),
	)
)
