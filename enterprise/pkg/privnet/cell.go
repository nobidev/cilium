//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package privnet

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/pkg/privnet/addressing"
	pncfg "github.com/cilium/cilium/enterprise/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/pkg/privnet/endpoints"
	health "github.com/cilium/cilium/enterprise/pkg/privnet/health/grpc"
	"github.com/cilium/cilium/enterprise/pkg/privnet/reconcilers"
)

var Cell = cell.Module(
	"private-networks",
	"Support for Private Networks",

	pncfg.Cell,
	reconcilers.Cell,
	endpoints.Cell,
	health.Cell,
	addressing.Cell,
)
