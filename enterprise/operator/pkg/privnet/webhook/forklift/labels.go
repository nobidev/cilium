// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package forklift

import "k8s.io/apimachinery/pkg/types"

type labeled interface{ GetLabels() map[string]string }

// GetPlanID returns the Forklift Plan UID, retrieved from the object labels.
func GetPlanID(obj labeled) types.UID {
	const key = "plan"
	return types.UID(obj.GetLabels()[key])
}

// GetVMID returns the VM ID in the target provider, retrieved from the object labels.
func GetVMID(obj labeled) string {
	const key = "vmID"
	return obj.GetLabels()[key]
}

// IsMigratedVM returns whether the given object resembles a migrated VM, according
// to its labels.
func IsMigratedVM(obj labeled) bool {
	return GetPlanID(obj) != "" && GetVMID(obj) != ""
}
