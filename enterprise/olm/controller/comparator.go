/*
Copyright (C) Isovalent, Inc. - All Rights Reserved.

NOTICE: All information contained herein is, and remains the property of
Isovalent Inc and its suppliers, if any. The intellectual and technical
concepts contained herein are proprietary to Isovalent Inc and its suppliers
and may be covered by U.S. and Foreign Patents, patents in process, and are
protected by trade secret or copyright law.  Dissemination of this information
or reproduction of this material is strictly forbidden unless prior written
permission is obtained from Isovalent Inc.
*/

package controller

import (
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const ciliumNonIdempotent = "cilium.io/helm-template-non-idempotent"

// Diff compares the current state passed as a map indexed by kind/namespace/name with the desired state.
// It then returns resources that need to be applied and resources that need to be deleted.
// Special logic has been built for non-idempotent resources as genSignedCert is used in Cilium charts, which makes them non-idempotent.
// To avoid hot looping they are only reconciled when the release versions, stored in labels, differ.
func Diff(desired []*unstructured.Unstructured, current map[string]*unstructured.Unstructured) (added, removed []*unstructured.Unstructured) {
	for _, d := range desired {
		key := fmt.Sprintf("%s/%s/%s", d.GetKind(), d.GetNamespace(), d.GetName())
		if val, ok := current[key]; !ok {
			added = append(added, d)
		} else {
			// Reconciliation of non idempotent resources
			// is only done when the version has changed
			if !isNonIdempotent(d) || hasChangedVersion(d, val) {
				added = append(added, d)
			}
			// Remove the desired entry from the list of existing resources so that we are left with entries that are not desired anymore
			delete(current, key)
		}
	}
	for _, v := range current {
		removed = append(removed, v)
	}
	return
}

// isNonIdempotent checks for labels, which mark a resource as non-idempotent
func isNonIdempotent(obj *unstructured.Unstructured) bool {
	labels := obj.GetLabels()
	return labels != nil && labels[ciliumNonIdempotent] == "true"
}

// hasChangedVersion checks whether the version has changed between two resources
func hasChangedVersion(desired *unstructured.Unstructured, current *unstructured.Unstructured) bool {
	cls := current.GetLabels()
	dls := desired.GetLabels()
	return cls == nil || dls == nil || cls[VersionLabelKey] != dls[VersionLabelKey]
}
