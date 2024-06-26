//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lb

import (
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlRuntime "sigs.k8s.io/controller-runtime"

	"github.com/cilium/cilium/operator/pkg/secretsync"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

var Cell = cell.Module(
	"standalone-lb-controlplane",
	"Standalone LoadBalancer controlplane",

	//exhaustruct:ignore
	cell.Config(Config{}),
	cell.Invoke(registerReconciler),
	cell.Provide(registerSecretSync),
	cell.ProvidePrivate(newNodeSource),
)

type Config struct {
	StandaloneLbEnabled          bool
	StandaloneLbSecretsNamespace string
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("standalone-lb-enabled", false, "Whether or not the standalone lb controlplane is enabled.")
	flags.String("standalone-lb-secrets-namespace", "cilium-secrets", "Namespace that should be used when syncing TLS secrets used by Standalone LB.")
}

type reconcilerParams struct {
	cell.In

	Logger    logrus.FieldLogger
	Lifecycle cell.Lifecycle
	JobGroup  job.Group
	Config    Config

	CtrlRuntimeManager ctrlRuntime.Manager
	Scheme             *runtime.Scheme

	NodeSource *ciliumNodeSource
}

func registerReconciler(params reconcilerParams) error {
	if !params.Config.StandaloneLbEnabled {
		return nil
	}

	if err := isovalentv1alpha1.AddToScheme(params.Scheme); err != nil {
		return fmt.Errorf("failed to add scheme: %w", err)
	}

	reconciler := newStandaloneLbReconciler(params.Logger, params.CtrlRuntimeManager.GetClient(), params.Scheme, params.NodeSource, &ingestor{}, params.Config.StandaloneLbSecretsNamespace)

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(hookContext cell.HookContext) error {
			// register reconciler to manager in lifecycle to ensure that CRDs are installed on the cluster
			if err := reconciler.SetupWithManager(params.CtrlRuntimeManager); err != nil {
				return fmt.Errorf("failed to setup standalone lb reconciler: %w", err)
			}

			return nil
		},
	})

	return nil
}

// registerSecretSync registers the Standalone LB controlplane for secret synchronization based on TLS secrets referenced
// by the LBFrontends.
func registerSecretSync(params reconcilerParams) secretsync.SecretSyncRegistrationOut {
	if !params.Config.StandaloneLbEnabled {
		return secretsync.SecretSyncRegistrationOut{}
	}

	return secretsync.SecretSyncRegistrationOut{
		SecretSyncRegistration: &secretsync.SecretSyncRegistration{
			RefObject:            &isovalentv1alpha1.LBFrontend{},
			RefObjectEnqueueFunc: enqueueTLSSecrets(params.CtrlRuntimeManager.GetClient(), params.Logger),
			RefObjectCheckFunc:   isReferencedByLBFrontend,
			SecretsNamespace:     params.Config.StandaloneLbSecretsNamespace,
		},
	}
}
