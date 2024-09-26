//nolint:goheader
// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package features

import (
	"github.com/cilium/hive/cell"
)

var AgentCell = cell.Module(
	"features-agent",
	"Feature definitions and gates for the agent",

	cell.Config(defaultFeatureGatesConfig),
	cell.Invoke(validateFeatureGates),
)

// OperatorCell checks the features in configmaps/cilium-config and
// updates the annotations to mark the config as invalid. This is shown
// in "cilium status" to the customer.
var OperatorCell = cell.Module(
	"features-operator",
	"Feature definitions and gates for the operator",

	cell.Config(defaultFeatureGatesConfig),
	cell.Invoke(registerFeatureGatesOperatorValidation),
)
