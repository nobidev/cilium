//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package k8s

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/k8s"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

func PrivateNetworkEndpointSliceResource(params k8s.CiliumResourceParams, mp workqueue.MetricsProvider, opts ...func(*metav1.ListOptions)) (resource.Resource[*iso_v1alpha1.PrivateNetworkEndpointSlice], error) {
	if !params.ClientSet.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped(params.ClientSet.IsovalentV1alpha1().PrivateNetworkEndpointSlices(metav1.NamespaceAll)),
		opts...,
	)
	return resource.New[*iso_v1alpha1.PrivateNetworkEndpointSlice](params.Lifecycle, lw, mp,
		resource.WithMetric("PrivateNetworkEndpointSlices"), resource.WithCRDSync(params.CRDSyncPromise),
	), nil
}
