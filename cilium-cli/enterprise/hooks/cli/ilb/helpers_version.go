//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import (
	"context"
	"errors"
	"fmt"

	"github.com/blang/semver/v4"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/clientset"
)

const (
	ciliumAgentPodLabelSelector = "app.kubernetes.io/name=cilium-agent"
)

func GetCiliumVersion(t T, clientset *clientset.Clientset) semver.Version {
	return GetCiliumVersionRaw(t.Context(), t, clientset, t.CiliumNamespace())
}

func GetCiliumVersionRaw(ctx context.Context, f FailureReporter, clientset *clientset.Clientset, ciliumNamespace string) semver.Version {
	// use of k8s.Client that supporteds Cilium version evaluation
	ciliumK8sClient := &k8s.Client{
		Clientset: clientset,
		Config:    newK8sClientRestConfig(f),
	}

	v, err := detectMinimumCiliumVersion(ctx, ciliumK8sClient, ciliumNamespace)
	if err != nil {
		f.Failedf("failed to evaluate cilium version: %s", err)
	}

	return *v
}

func detectMinimumCiliumVersion(ctx context.Context, k8sClient *k8s.Client, ciliumNamespace string) (*semver.Version, error) {
	podList, err := k8sClient.Clientset.CoreV1().Pods(ciliumNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: ciliumAgentPodLabelSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list cilium agent pods: %w", err)
	}

	if len(podList.Items) == 0 {
		return nil, errors.New("no cilium agent pods found")
	}

	var minVersion *semver.Version

	for _, ciliumPod := range podList.Items {
		podVersion, err := k8sClient.GetCiliumVersion(ctx, &ciliumPod)
		if err != nil {
			return nil, fmt.Errorf("unable to parse Cilium version on pod %q: %w", ciliumPod.Name, err)
		}
		if minVersion == nil || podVersion.LT(*minVersion) {
			minVersion = podVersion
		}
	}

	if minVersion == nil {
		return nil, errors.New("unable to detect minimum Cilium version")
	}

	return minVersion, nil
}
