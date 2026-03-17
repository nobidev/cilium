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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/tables"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/webhook/config"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type Reflector struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	db *statedb.DB
	cl dynamic.Interface
}

func newReflector(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	DB     *statedb.DB
	Client dynamic.Interface
}) (*Reflector, error) {
	reflector := &Reflector{
		log: in.Log,
		jg:  in.JobGroup,

		cfg: in.Config,

		db: in.DB,
		cl: in.Client,
	}

	if in.Config.Enabled && in.Client == nil {
		return nil, errors.New("private networks requires Kubernetes support to be enabled")
	}

	return reflector, nil
}

func (r *Reflector) ForProviders(tbl statedb.RWTable[Provider]) error {
	if !r.cfg.Enabled {
		return nil
	}

	return k8s.RegisterReflector(r.jg, r.db, k8s.ReflectorConfig[Provider]{
		Name:  "to-table",
		Table: tbl,
		ListerWatcher: r.listerWatcher(schema.GroupVersionResource{
			Group:    "forklift.konveyor.io",
			Version:  "v1beta1",
			Resource: "providers",
		}),

		Transform: func(rt statedb.ReadTxn, obj any) (Provider, bool) {
			uns, ok := obj.(*unstructured.Unstructured)
			if !ok {
				return Provider{}, false
			}

			defer r.recoverDigError(uns)
			return Provider{
				NamespacedNameWithUID: NewNamespacedNameWithUID(uns),

				Type: ProviderType(dig[string](uns.Object, digModeLoose, "spec", "type")),
			}, true
		},
	})
}

func (r *Reflector) ForPlans(tbl statedb.RWTable[Plan]) error {
	if !r.cfg.Enabled {
		return nil
	}

	return k8s.RegisterReflector(r.jg, r.db, k8s.ReflectorConfig[Plan]{
		Name:  "to-table",
		Table: tbl,
		ListerWatcher: r.listerWatcher(schema.GroupVersionResource{
			Group:    "forklift.konveyor.io",
			Version:  "v1beta1",
			Resource: "plans",
		}),

		Transform: func(rt statedb.ReadTxn, obj any) (Plan, bool) {
			uns, ok := obj.(*unstructured.Unstructured)
			if !ok {
				return Plan{}, false
			}

			defer r.recoverDigError(uns)
			return Plan{
				NamespacedNameWithUID: NewNamespacedNameWithUID(uns),
				SourceProvider: NamespacedNameWithUID{
					NamespacedName: tables.NamespacedName{
						Namespace: dig[string](uns.Object, digModeStrict, "spec", "provider", "source", "namespace"),
						Name:      dig[string](uns.Object, digModeStrict, "spec", "provider", "source", "name"),
					},
					UID: types.UID(dig[string](uns.Object, digModeStrict, "spec", "provider", "source", "uid")),
				},
				PreserveStaticIPs: dig[bool](uns.Object, digModeLoose, "spec", "preserveStaticIPs"),
			}, true
		},
	})
}

func (r *Reflector) listerWatcher(resource schema.GroupVersionResource) cache.ListerWatcher {
	nri := r.cl.Resource(resource)
	return &cache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			return nri.List(ctx, opts)
		},
		WatchFuncWithContext: func(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
			return nri.Watch(ctx, opts)
		},
	}
}

type errDig struct{ error }

func (r *Reflector) recoverDigError(obj *unstructured.Unstructured) {
	got := recover()
	if got == nil {
		return
	}

	err, ok := got.(errDig)
	if !ok {
		panic(got)
	}

	r.log.Warn("Failed to parse forklift resource",
		logfields.Error, err.error,
		logfields.Resource, obj.GetKind(),
		logfields.K8sNamespace, obj.GetNamespace(),
		logfields.Name, obj.GetName(),
	)
}

type digMode bool

const (
	// digModeStrict ensures that the target field exists.
	digModeStrict = digMode(true)
	// digModeLoose allows the target field to not be present.
	digModeLoose = digMode(false)
)

func dig[T any](root map[string]any, mode digMode, fields ...string) (out T) {
	// Mimics the same logic used in the unstructured package.
	var jsonPath = func() string { return "." + strings.Join(fields, ".") }

	got, found, err := unstructured.NestedFieldNoCopy(root, fields...)
	if err != nil {
		panic(errDig{err})
	}

	if !found {
		if mode == digModeLoose {
			return out
		}

		panic(errDig{fmt.Errorf("%s accessor error: not found", jsonPath())})
	}

	out, ok := got.(T)
	if !ok {
		panic(errDig{fmt.Errorf("%s accessor error: %v is of type %T, expected %T", jsonPath(), got, got, out)})
	}

	return out
}

func newDynamicClient(cfg config.Config, client client.Clientset) (dynamic.Interface, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	if !client.IsEnabled() {
		return nil, errors.New("private networks requires Kubernetes support to be enabled")
	}

	out, err := dynamic.NewForConfig(client.RestConfig())
	if err != nil {
		return nil, fmt.Errorf("unable to create dynamic client: %w", err)
	}

	return out, nil
}
