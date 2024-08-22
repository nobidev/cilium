//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package policy

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/enterprise/pkg/encryption/policy/types"
	"github.com/cilium/cilium/enterprise/pkg/maps/encryptionpolicymap"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
)

// newNodeConfig returns the necessary node_config.h definitions to enable the
// encryption policy datapath
func newNodeConfig(cfg types.Config) defines.NodeOut {
	if !cfg.EnableEncryptionPolicy {
		return defines.NodeOut{}
	}

	return defines.NodeOut{
		NodeDefines: map[string]string{
			"ENABLE_ENCRYPTION_POLICY": "1",
		},
	}
}

type reconcilerParams struct {
	cell.In

	JobGroup job.Group
	DB       *statedb.DB

	Config    types.Config
	PolicyMap *encryptionpolicymap.PolicyMap
	Table     statedb.RWTable[*EncryptionPolicyEntry]

	Params reconciler.Params
}

// startEncryptionPolicyReconciler starts a BPF map reconciler that reconciles the contents of the
// encryption-policy StateDB table with the encryption-policy BPF map
func startEncryptionPolicyReconciler(params reconcilerParams) (reconciler.Reconciler[*EncryptionPolicyEntry], error) {
	if !params.Config.EnableEncryptionPolicy {
		return nil, nil
	}

	bpf.RegisterTablePressureMetricsJob[*EncryptionPolicyEntry, *encryptionpolicymap.PolicyMap](
		params.JobGroup,
		params.DB,
		params.Table.ToTable(),
		params.PolicyMap,
	)

	return reconciler.Register[*EncryptionPolicyEntry](
		// params
		params.Params,
		// table
		params.Table,
		// clone
		func(e *EncryptionPolicyEntry) *EncryptionPolicyEntry {
			// We can do a shallow copy here and share the Owners slice,
			// since the reconciler only writes to the status field
			cpy := *e
			return &cpy
		},
		// setStatus
		func(e *EncryptionPolicyEntry, s reconciler.Status) *EncryptionPolicyEntry {
			e.Status = s
			return e
		},
		// getStatus
		func(e *EncryptionPolicyEntry) reconciler.Status {
			return e.Status
		},
		// ops
		bpf.NewMapOps[*EncryptionPolicyEntry](params.PolicyMap.Map),
		// batchOps
		nil,
	)
}
