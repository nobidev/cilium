// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package forklift

import (
	"cmp"
	"strconv"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/tables"
)

// NamespacedNameWithUID represents a namespace and name pair, complemented by a UID.
type NamespacedNameWithUID struct {
	tables.NamespacedName `json:",inline" yaml:",inline"`
	UID                   types.UID
}

func (nnu NamespacedNameWithUID) String() string    { return nnu.NamespacedName.String() }
func (nnu NamespacedNameWithUID) GetUID() types.UID { return nnu.UID }

func (nnu NamespacedNameWithUID) TableHeader() []string {
	return []string{"Namespace", "Name", "UID"}
}

func (nnu NamespacedNameWithUID) TableRow() []string {
	return []string{nnu.Namespace, nnu.Name, string(nnu.UID)}
}

// NewNamespacedNameWithUID creates a new NamespacedNameWithUID instance for the given object.
func NewNamespacedNameWithUID(obj metav1.Object) NamespacedNameWithUID {
	return NamespacedNameWithUID{
		NamespacedName: tables.NamespacedName{
			Namespace: obj.GetNamespace(),
			Name:      obj.GetName(),
		},
		UID: obj.GetUID(),
	}
}

func uidIndex[T interface{ GetUID() types.UID }]() statedb.Index[T, types.UID] {
	return statedb.Index[T, types.UID]{
		Name: "uid",
		FromObject: func(obj T) index.KeySet {
			return index.NewKeySet(index.String(string(obj.GetUID())))
		},
		FromKey: func(uid types.UID) index.Key {
			return index.String(string(uid))
		},
		FromString: index.FromString,
		Unique:     true,
	}
}

// ----- Provider ----- //

// ProviderType represents the type of a provider.
type ProviderType string

const (
	// ProviderTypeVsphere represents the vSphere provider type.
	ProviderTypeVsphere = ProviderType("vsphere")
)

// Provider represents a Forklift Provider instance observed from Kubernetes.
type Provider struct {
	NamespacedNameWithUID `json:",inline" yaml:",inline"`

	// Type is the type of the given Provider.
	Type ProviderType
}

var _ statedb.TableWritable = Provider{}

func (p Provider) TableHeader() []string {
	return append(p.NamespacedNameWithUID.TableHeader(), "Type")
}

func (p Provider) TableRow() []string {
	return append(p.NamespacedNameWithUID.TableRow(), cmp.Or(string(p.Type), "?"))
}

var (
	providersUIDIndex = uidIndex[Provider]()

	// ProviderByUID queries the providers table by UID.
	ProviderByUID = providersUIDIndex.Query
)

func NewProvidersTable(db *statedb.DB) (statedb.RWTable[Provider], error) {
	return statedb.NewTable(
		db,
		"privnet-forklift-providers",
		providersUIDIndex,
	)
}

// ----- Plan ----- //

// Plan represents a Forklift migration plan instance observed from Kubernetes.
type Plan struct {
	NamespacedNameWithUID `json:",inline" yaml:",inline"`

	// SourceProvider references the source provider of the migration plan.
	SourceProvider NamespacedNameWithUID

	// PreserveStaticIPs is true if static IPs are requested to be preserved.
	PreserveStaticIPs bool
}

var _ statedb.TableWritable = Plan{}

func (p Plan) TableHeader() []string {
	return append(p.NamespacedNameWithUID.TableHeader(), "SourceProvider", "PreserveStaticIPs")
}

func (p Plan) TableRow() []string {
	return append(
		p.NamespacedNameWithUID.TableRow(),
		p.SourceProvider.String(),
		strconv.FormatBool(p.PreserveStaticIPs),
	)
}

var (
	plansUIDIndex = uidIndex[Plan]()

	// PlanByUID queries the plans table by UID.
	PlanByUID = plansUIDIndex.Query
)

func NewPlansTable(db *statedb.DB) (statedb.RWTable[Plan], error) {
	return statedb.NewTable(
		db,
		"privnet-forklift-plans",
		plansUIDIndex,
	)
}
