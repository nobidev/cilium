//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package status

import (
	"bytes"
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"

	ciliumClientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
)

type execClient struct {
	k8sClient    kubernetes.Interface
	ciliumClient ciliumClientset.Interface
	restConfig   *rest.Config
}

func (c *execClient) ExecInPod(ctx context.Context, namespace, pod, container string, command []string) (stdout bytes.Buffer, stderr bytes.Buffer, err error) {
	scheme := runtime.NewScheme()
	if err = corev1.AddToScheme(scheme); err != nil {
		return stdout, stderr, fmt.Errorf("error adding to scheme: %w", err)
	}

	url := c.k8sClient.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(
			&corev1.PodExecOptions{
				Command:   command,
				Container: container,
				Stdout:    true,
				Stderr:    true,
			},
			runtime.NewParameterCodec(scheme),
		).URL()

	exec, err := remotecommand.NewSPDYExecutor(c.restConfig, "POST", url)
	if err != nil {
		return stdout, stderr, fmt.Errorf("error while creating executor: %w", err)
	}

	return stdout, stderr, exec.StreamWithContext(ctx,
		remotecommand.StreamOptions{
			Stdout: &stdout,
			Stderr: &stderr,
		},
	)
}
