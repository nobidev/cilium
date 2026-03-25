// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vrf

import (
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

func NewVRFTableAndReflector(jg job.Group, db *statedb.DB, cs client.Clientset) (statedb.Table[VRF], error) {
	tbl, err := NewVRFTable(db)
	if err != nil {
		return nil, err
	}
	if !cs.IsEnabled() {
		return tbl, nil
	}

	lw := utils.ListerWatcherFromTyped[*ciliumv2.CiliumVRFList](cs.CiliumV2().CiliumVRFs())

	err = k8s.RegisterReflector(jg, db, k8s.ReflectorConfig[VRF]{
		Name:          "vrf",
		Table:         tbl,
		ListerWatcher: lw,
		MetricScope:   "CiliumVRF",
		Transform: func(_ statedb.ReadTxn, obj any) (VRF, bool) {
			cv, ok := obj.(*ciliumv2.CiliumVRF)
			if !ok {
				return VRF{}, false
			}
			return VRF{
				Name:         cv.Name,
				ID:           cv.Spec.ID,
				Table:        cv.Spec.Table,
				NodeSelector: cv.Spec.NodeSelector,
				Selector:     cv.Spec.Selector,
				Interfaces:   cv.Spec.Interfaces,
			}, true
		},
	})
	return tbl, err
}
