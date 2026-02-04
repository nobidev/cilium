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
	"bytes"

	clientset "k8s.io/client-go/kubernetes"

	"github.com/cilium/cilium/cilium-cli/k8s"
)

func execIntoPod(t T, clientset *clientset.Clientset, namespace string, pod string, container string, command []string) (bytes.Buffer, bytes.Buffer, error) {
	// use of k8s.Client that supports Cilium execing into a pod
	ciliumK8sClient := &k8s.Client{
		Clientset: clientset,
		Config:    newK8sClientRestConfig(t),
	}

	return ciliumK8sClient.ExecInPodWithStderr(t.Context(), namespace, pod, container, command)
}
