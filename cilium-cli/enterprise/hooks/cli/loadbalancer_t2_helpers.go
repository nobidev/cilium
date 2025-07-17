// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/api"
)

type reader struct {
	r    io.ReadCloser
	name string
}

func podReaders(ctx context.Context, ciliumNamespace, podNameFilter string, follow bool) ([]reader, error) {
	var readers []reader

	k8sClient, _ := api.GetK8sClientContextValue(ctx)

	pods, err := k8sClient.ListPods(ctx, ciliumNamespace, metav1.ListOptions{
		LabelSelector: "name=cilium-envoy",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list T2 Envoy pods: %w", err)
	}

	for _, p := range pods.Items {
		if podNameFilter != "" && p.Name != podNameFilter {
			continue
		}

		r := k8sClient.Clientset.CoreV1().Pods(p.Namespace).GetLogs(p.Name, &corev1.PodLogOptions{
			Follow: follow,
		})
		s, err := r.Stream(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to open log stream for pod %q: %w", p.Name, err)
		}

		readers = append(readers, reader{r: s, name: p.Name})
	}

	return readers, nil
}

func fileReaders(files []string) ([]reader, error) {
	var readers []reader

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("failed to open file %q: %w", file, err)
		}
		readers = append(readers, reader{r: f, name: filepath.Base(file)})
	}

	return readers, nil
}
