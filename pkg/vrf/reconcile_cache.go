// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vrf

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/k8s/client"
)

type reconcileCache struct {
	toAdd      []*VRF
	toRemove   map[string]*VRF
	toUpdate   []*VRF
	namespaces map[string]map[string]string
}

func (rc *reconcileCache) populateNamespaces(ctx context.Context, clientset client.Clientset) error {
	nsList, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list namespaces: %w", err)
	}
	if rc.namespaces == nil {
		rc.namespaces = make(map[string]map[string]string, len(nsList.Items))
	}
	for k := range rc.namespaces {
		delete(rc.namespaces, k)
	}
	for _, ns := range nsList.Items {
		rc.namespaces[ns.Name] = ns.Labels
	}
	return nil
}

// reset clears the reconcile cache for reuse, retaining allocated memory.
func (rc *reconcileCache) reset() {
	rc.toAdd = rc.toAdd[:0]
	rc.toUpdate = rc.toUpdate[:0]
	clear(rc.toRemove)
	clear(rc.namespaces)
}

// namespaceLabels returns the labels for the given namespace from the cache.
func (rc *reconcileCache) namespaceLabels(ns string) (map[string]string, bool) {
	labels, ok := rc.namespaces[ns]
	return labels, ok
}
