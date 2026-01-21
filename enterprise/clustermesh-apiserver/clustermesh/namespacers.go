// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package clustermesh

import (
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/cilium/cilium/clustermesh-apiserver/clustermesh"
	iso_api_v1a1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

type GenericNamespacer[T runtime.Object] struct {
	extract func(T) string
}

func (gn *GenericNamespacer[T]) ExtractNamespace(event resource.Event[T]) (namespace string) {
	return gn.extract(event.Object)
}

// ----- PrivateNetworkEndpointSlice ----- //

func newPrivateNetworkEndpointSliceNamespacer() clustermesh.Namespacer[*iso_api_v1a1.PrivateNetworkEndpointSlice] {
	return &GenericNamespacer[*iso_api_v1a1.PrivateNetworkEndpointSlice]{
		extract: func(obj *iso_api_v1a1.PrivateNetworkEndpointSlice) string {
			return obj.GetNamespace()
		},
	}
}
