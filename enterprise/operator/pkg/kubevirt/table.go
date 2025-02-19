//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package kubevirt

import (
	"slices"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/enterprise/pkg/ipmigration/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/time"
)

const KubeVirtVMTableName = "kubevirt-vm"

type KubeVirtVM struct {
	VMName resource.Key
	Pods   []resource.Key

	PrimaryPod       resource.Key
	PrimaryReadyTime time.Time

	IPAM types.DetachedIpamAddressPair

	Status reconciler.Status
}

func (k *KubeVirtVM) DeepCopy() *KubeVirtVM {
	return &KubeVirtVM{
		VMName: k.VMName,
		Pods:   slices.Clone(k.Pods),

		PrimaryPod:       k.PrimaryPod,
		PrimaryReadyTime: k.PrimaryReadyTime,

		IPAM:   k.IPAM,
		Status: k.Status,
	}
}

// equals checks if two KubeVirtVM objects are equal, ignoring the contents of Status.
func (k *KubeVirtVM) equals(other *KubeVirtVM) bool {
	if k == other {
		return true
	}

	if (k == nil) != (other == nil) {
		return false
	}

	return k.VMName == other.VMName &&
		k.PrimaryPod == other.PrimaryPod &&
		k.PrimaryReadyTime == other.PrimaryReadyTime &&
		slices.Equal(k.Pods, other.Pods) &&
		k.IPAM.DeepEqual(&other.IPAM)
}

func (k *KubeVirtVM) TableHeader() []string {
	return []string{
		"VMName",
		"Pods",
		"PrimaryPod",
		"PrimaryReadyTime",
		"IPAM",
		"Status",
	}
}

func (k *KubeVirtVM) TableRow() []string {
	pods := make([]string, 0, len(k.Pods))
	for _, pod := range k.Pods {
		pods = append(pods, pod.String())
	}

	return []string{
		k.VMName.String(),
		strings.Join(pods, ","),
		k.PrimaryPod.String(),
		k.PrimaryReadyTime.String(),
		k.IPAM.String(),
		k.Status.String(),
	}
}

var KubeVirtVMPodIndex = statedb.Index[*KubeVirtVM, resource.Key]{
	Name: "pod",
	FromObject: func(k *KubeVirtVM) index.KeySet {
		return index.StringerSlice(k.Pods)
	},
	FromKey:    index.Stringer[resource.Key],
	FromString: index.FromString,
	Unique:     true,
}

var KubeVirtVMNameIndex = statedb.Index[*KubeVirtVM, resource.Key]{
	Name: "vm-name",
	FromObject: func(k *KubeVirtVM) index.KeySet {
		return index.NewKeySet(index.Stringer(k.VMName))
	},
	FromKey:    index.Stringer[resource.Key],
	FromString: index.FromString,
	Unique:     true,
}

func NewKubeVirtVMTable(cfg Config, db *statedb.DB) (statedb.RWTable[*KubeVirtVM], error) {
	if !cfg.EnableKubeVirtVMMigration {
		return nil, nil
	}
	tbl, err := statedb.NewTable(
		KubeVirtVMTableName,
		KubeVirtVMNameIndex,
		KubeVirtVMPodIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}
