// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package securitygroups

import (
	"errors"
	"log/slog"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	evpnConfig "github.com/cilium/cilium/enterprise/pkg/evpn/config"
	"github.com/cilium/cilium/enterprise/pkg/evpn/securitygroups/tables"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	clientv1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/promise"
)

type securityGroups struct {
	log      *slog.Logger
	jobGroup job.Group
	cfg      evpnConfig.Config
	db       *statedb.DB
	table    statedb.RWTable[tables.SecurityGroup]
	client   clientv1alpha1.FabricSecurityGroupInterface
}

func newSecurityGroups(in struct {
	cell.In
	Logger   *slog.Logger
	JobGroup job.Group
	Config   evpnConfig.Config
	DB       *statedb.DB
	Table    statedb.RWTable[tables.SecurityGroup]
	Client   client.Clientset
}) (*securityGroups, error) {
	r := &securityGroups{
		log:      in.Logger,
		cfg:      in.Config,
		jobGroup: in.JobGroup,
		db:       in.DB,
		table:    in.Table,
	}
	if !in.Config.Enabled || !in.Config.SecurityGroupTagsEnabled {
		return r, nil
	}
	if !in.Client.IsEnabled() {
		return nil, errors.New("FabricSecurityGroup reflection requires Kubernetes support to be enabled")
	}
	r.client = in.Client.IsovalentV1alpha1().FabricSecurityGroups()
	return r, nil
}

func (r *securityGroups) registerK8sReflector(sync promise.Promise[synced.CRDSync]) error {
	if !r.cfg.Enabled || !r.cfg.SecurityGroupTagsEnabled {
		return nil
	}

	cfg := k8s.ReflectorConfig[tables.SecurityGroup]{
		Name:          "to-table",
		Table:         r.table,
		ListerWatcher: utils.ListerWatcherFromTyped(r.client),
		MetricScope:   "SecurityGroup",
		CRDSync:       sync,
		Transform: func(txn statedb.ReadTxn, obj any) (tables.SecurityGroup, bool) {
			fsg, ok := obj.(*v1alpha1.FabricSecurityGroup)
			if !ok {
				return tables.SecurityGroup{}, false
			}
			return r.transform(fsg)
		},
	}
	return k8s.RegisterReflector(r.jobGroup, r.db, cfg)
}

func (r *securityGroups) transform(obj *v1alpha1.FabricSecurityGroup) (tables.SecurityGroup, bool) {
	if obj == nil || obj.Name == "" {
		return tables.SecurityGroup{}, false
	}

	id, err := strconv.ParseUint(obj.Name, 10, 16)
	if err != nil {
		r.log.Warn("Skipping FabricSecurityGroup with invalid name",
			logfields.Name, obj.Name,
			logfields.Error, err,
		)
		return tables.SecurityGroup{}, false
	}

	res := tables.SecurityGroup{
		GroupID: uint16(id),
	}
	if obj.Spec.EndpointSelector != nil {
		res.EndpointSelector = policyTypes.NewLabelSelector(api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, obj.Spec.EndpointSelector))
	}
	return res, true
}
