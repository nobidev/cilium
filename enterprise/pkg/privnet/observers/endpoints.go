//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package observers

import (
	"github.com/cilium/stream"

	"github.com/cilium/cilium/enterprise/pkg/privnet/kvstore"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/kvstore/store"
)

type (
	// EndpointEvents is a sequence of private network endpoint events.
	EndpointEvents = Events[*kvstore.Endpoint, resource.EventKind]
)

// PrivateNetworkEndpoints implements [store.Observer] for private network endpoints.
type PrivateNetworkEndpoints struct {
	*Generic[*kvstore.Endpoint, resource.EventKind]
}

var (
	_ store.Observer                    = (*PrivateNetworkEndpoints)(nil)
	_ stream.Observable[EndpointEvents] = (*PrivateNetworkEndpoints)(nil)
)

func NewPrivateNetworkEndpoints() *PrivateNetworkEndpoints {
	return &PrivateNetworkEndpoints{
		Generic: NewGeneric[*kvstore.Endpoint, resource.EventKind](),
	}
}

func (o *PrivateNetworkEndpoints) OnUpdate(k store.Key) {
	if ep, ok := k.(*kvstore.ValidatingEndpoint); ok {
		o.Queue(resource.Upsert, &ep.Endpoint)
	}
}

func (o *PrivateNetworkEndpoints) OnDelete(k store.NamedKey) {
	if ep, ok := k.(*kvstore.ValidatingEndpoint); ok {
		o.Queue(resource.Delete, &ep.Endpoint)
	}
}

func (o *PrivateNetworkEndpoints) OnSync() {
	o.Queue(resource.Sync, nil)
}
