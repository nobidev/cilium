//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package extlb

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlRuntime "sigs.k8s.io/controller-runtime"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

var DefaultConfig = Config{
	ExtLBEnabled: false,
}

// Cell provides controllers for managing connections to backend Kubernetes
// clusters, watching the resources in those clusters, and configuring Isovalent
// Load Balancer resources accordingly. This enables this Cilium cluster to act
// as a load balancer for those backend clusters. For example, to provide
// connectivity for external Services of type LoadBalancer, acting as the Cloud
// Load Balancer for those Services and providing an ExternalIP. May be extended
// in the future to support other types of resources and configuration options.
var Cell = cell.Module(
	"loadbalancer-extlb-controlplane", "The External Load Balancer control plane",

	cell.Config(DefaultConfig),
	cell.Invoke(registerExternalLBReconcilers),
	cell.ProvidePrivate(newRemoteClusterManager),
)

type Config struct {
	ExtLBEnabled bool `mapstructure:"loadbalancer-extlb-enabled"`
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("loadbalancer-extlb-enabled", c.ExtLBEnabled, "Enable the External Load Balancer control plane")
}

type reconcilerParams struct {
	cell.In

	Logger           *slog.Logger
	Manager          ctrlRuntime.Manager
	Scheme           *runtime.Scheme
	Config           Config
	RemoteClusterMgr *remoteClusterManager
}

func registerExternalLBReconcilers(params reconcilerParams) error {
	if !params.Config.ExtLBEnabled {
		return nil
	}

	if err := isovalentv1alpha1.AddToScheme(params.Scheme); err != nil {
		return fmt.Errorf("failed to add isovalent scheme: %w", err)
	}

	reconciler := newLBK8sBackendClusterReconciler(
		params.Logger,
		params.Manager.GetClient(),
		params.Scheme,
		params.RemoteClusterMgr,
		params.Config,
	)

	return reconciler.SetupWithManager(params.Manager)
}
