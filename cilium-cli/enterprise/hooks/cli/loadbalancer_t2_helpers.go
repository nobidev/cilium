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

func podReaders(ctx context.Context, namespace, labelSelector, podNameFilter string, follow bool, sinceSeconds *int64) ([]reader, error) {
	var readers []reader

	k8sClient, _ := api.GetK8sClientContextValue(ctx)

	pods, err := k8sClient.ListPods(ctx, namespace, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods with selector %q in namespace %q: %w", labelSelector, namespace, err)
	}

	for _, p := range pods.Items {
		if podNameFilter != "" && p.Name != podNameFilter {
			continue
		}

		opts := &corev1.PodLogOptions{
			Follow: follow,
		}
		if sinceSeconds != nil {
			opts.SinceSeconds = sinceSeconds
		}

		r := k8sClient.Clientset.CoreV1().Pods(p.Namespace).GetLogs(p.Name, opts)
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
