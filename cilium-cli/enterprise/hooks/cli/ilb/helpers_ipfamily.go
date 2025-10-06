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
	"fmt"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	k8s "github.com/cilium/cilium/pkg/k8s/slim/k8s/clientset"
)

func IPFamilyInfo(ctx context.Context, k8sCli *k8s.Clientset, ciliumNamespace string) (bool, bool, error) {
	configmap, err := k8sCli.CoreV1().ConfigMaps(ciliumNamespace).Get(ctx, "cilium-config", metav1.GetOptions{})
	if err != nil {
		return false, false, fmt.Errorf("failed to retrieve Cilium Configmap: %w", err)
	}

	ipv4EnabledString, exists := configmap.Data["enable-ipv4"]
	if !exists {
		ipv4EnabledString = "false"
	}

	ipv6EnabledString, exists := configmap.Data["enable-ipv6"]
	if !exists {
		ipv6EnabledString = "false"
	}

	ipv4Enabled, err := strconv.ParseBool(ipv4EnabledString)
	if err != nil {
		ipv4Enabled = false
	}

	ipv6Enabled, err := strconv.ParseBool(ipv6EnabledString)
	if err != nil {
		ipv6Enabled = false
	}

	return ipv4Enabled, ipv6Enabled, nil
}
