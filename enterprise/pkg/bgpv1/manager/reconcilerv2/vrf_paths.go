// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"context"
	"errors"
	"log/slog"

	entTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/bgp/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgp/types"
)

// VRFPaths is a map type that contains service paths for a VRF, key being the VRF name.
type VRFPaths map[string]reconciler.ResourceAFPathsMap

type ReconcileVRFPathsParams struct {
	Logger       *slog.Logger
	Ctx          context.Context
	BGPInstance  *EnterpriseBGPInstance
	CurrentPaths VRFPaths
	DesiredPaths VRFPaths
}

func ReconcileVRFPaths(p ReconcileVRFPathsParams) error {
	var err error
	for vrf, desiredVRFPaths := range p.DesiredPaths {
		// desiredPaths can be nil, in which case we need to clean up the paths for this VRF.
		// reconcileVRFResourcePaths should handle nil desiredPaths.
		updatedVRFPaths, rErr := reconcileVRFResourcePaths(p, vrf, p.CurrentPaths[vrf], desiredVRFPaths)
		if rErr == nil && len(updatedVRFPaths) == 0 {
			delete(p.CurrentPaths, vrf)
		} else {
			p.CurrentPaths[vrf] = updatedVRFPaths
		}
		err = errors.Join(err, rErr)
	}
	return err
}

func reconcileVRFResourcePaths(p ReconcileVRFPathsParams, vrfName string, currentPaths, desiredPaths reconciler.ResourceAFPathsMap) (reconciler.ResourceAFPathsMap, error) {
	if currentPaths == nil {
		currentPaths = make(reconciler.ResourceAFPathsMap)
	}
	if desiredPaths == nil {
		desiredPaths = make(reconciler.ResourceAFPathsMap)
	}
	if len(desiredPaths) == 0 {
		// cleanup all current resource paths
		for resourceKey := range currentPaths {
			desiredPaths[resourceKey] = nil // mark resource for deletion
		}
	}
	updatedSvcPaths, err := reconciler.ReconcileResourceAFPaths(reconciler.ReconcileResourceAFPathsParams{
		Logger: p.Logger.With(
			types.InstanceLogField, p.BGPInstance.Name,
			entTypes.VRFLogField, vrfName,
		),
		Ctx:                    p.Ctx,
		Router:                 p.BGPInstance.Router,
		DesiredResourceAFPaths: desiredPaths,
		CurrentResourceAFPaths: currentPaths,
	})
	return updatedSvcPaths, err
}
