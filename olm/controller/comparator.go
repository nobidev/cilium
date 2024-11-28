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

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Compare the current state passed as a map indexed by kind/namespace/name with the desired state.
// It then returns resources that need to be applied and resources that need to be deleted.
// Special logic has been built for secrets as genSignedCert is used in Cilium charts, which makes them non-idempotent.
// To avoid hot looping they are only reconciled when the release versions, stored in labels, differ.
func Compare(desired []*unstructured.Unstructured, current map[string]*unstructured.Unstructured) (toApply, toRemove []*unstructured.Unstructured) {
	for _, d := range desired {
		key := fmt.Sprintf("%s/%s/%s", d.GetKind(), d.GetNamespace(), d.GetName())
		if val, ok := current[key]; !ok {
			toApply = append(toApply, d)
		} else {
			// Reconciliation of secrets disabled as they are not idempotent
			if d.GetKind() != "Secret" {
				toApply = append(toApply, d)
			} else {
				labels, ok := val.Object["metadata"].(map[string]interface{})["labels"]
				if !ok || !apiequality.Semantic.DeepEqual(d.Object["metadata"].(map[string]interface{})["labels"].(map[string]interface{})["app.kubernetes.io/version"],
					labels.(map[string]interface{})["app.kubernetes.io/version"]) {
					toApply = append(toApply, d)
				}
			}
			// Remove the desired entry from the list of existing resources so that we are left with entries that are not desired anymore
			delete(current, key)
		}
	}
	for _, v := range current {
		toRemove = append(toRemove, v)
	}
	return
}

// TODO: Write unit tests for the above, at least one positive and one negative and to cover the secret scenarios
