// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilers

import (
	"errors"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/k8s"
	iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	cs_iso_v1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

var PrivateNetworksCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite PrivateNetworks table.
		tables.NewPrivateNetworksTable,

		// Provides the reconciler handling private networks.
		newPrivateNetworks,
	),

	cell.Provide(
		// Provides the ReadOnly PrivateNetworks table.
		statedb.RWTable[tables.PrivateNetwork].ToTable,
	),

	cell.Invoke(
		// Registers the k8s to table reflector.
		(*PrivateNetworks).registerK8sReflector,
	),
)

type PrivateNetworks struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	db  *statedb.DB
	tbl statedb.RWTable[tables.PrivateNetwork]

	client cs_iso_v1alpha1.ClusterwidePrivateNetworkInterface
}

func newPrivateNetworks(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	DB    *statedb.DB
	Table statedb.RWTable[tables.PrivateNetwork]

	Client client.Clientset
}) (*PrivateNetworks, error) {
	reconciler := &PrivateNetworks{
		log: in.Log,
		jg:  in.JobGroup,
		cfg: in.Config,
		db:  in.DB,
		tbl: in.Table,
	}

	if !in.Config.Enabled {
		return reconciler, nil
	}

	if !in.Client.IsEnabled() {
		return nil, errors.New("private networks requires Kubernetes support to be enabled")
	}

	reconciler.client = in.Client.IsovalentV1alpha1().ClusterwidePrivateNetworks()
	return reconciler, nil
}

func (pn *PrivateNetworks) registerK8sReflector() error {
	if !pn.cfg.Enabled {
		return nil
	}

	return k8s.RegisterReflector(pn.jg, pn.db, k8s.ReflectorConfig[tables.PrivateNetwork]{
		Name:          "to-table",
		Table:         pn.tbl,
		ListerWatcher: utils.ListerWatcherFromTyped(pn.client),
		Transform: func(txn statedb.ReadTxn, obj any) (tables.PrivateNetwork, bool) {
			privnet, ok := obj.(*iso_v1alpha1.ClusterwidePrivateNetwork)
			if !ok {
				return tables.PrivateNetwork{}, false
			}

			return tables.PrivateNetwork{
				Name: tables.NetworkName(privnet.Name),
			}, true
		},
	})
}
