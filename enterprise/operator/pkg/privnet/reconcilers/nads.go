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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	nadclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	nadclientv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1"
	corev1 "k8s.io/api/core/v1"
	apiextclientv1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/config"
	"github.com/cilium/cilium/enterprise/operator/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
)

// NetworkAttachmentDefinitionsCell groups the NetworkAttachmentDefinition reconciliation
// operations that need to be performed by all operator replicas. Any operation that depends
// on leader election must be configured in a separate cell.
var NetworkAttachmentDefinitionsCell = cell.Group(
	cell.ProvidePrivate(
		// Provides the ReadWrite NetworkAttachmentDefinitions table.
		tables.NewNetworkAttachmentDefinitionsTable,

		// Provides the client to interact with NetworkAttachmentDefinitions.
		newNADsClient,

		// Provides the reconciler handling NetworkAttachmentDefinitions.
		newNetworkAttachmentDefinitions,
	),

	cell.Provide(
		// Provides the ReadOnly NetworkAttachmentDefinitions table.
		statedb.RWTable[tables.NetworkAttachmentDefinition].ToTable,
	),

	cell.Invoke(
		// Registers the k8s to table reflector.
		(*NetworkAttachmentDefinitions).registerK8sReflector,
	),
)

type NetworkAttachmentDefinitions struct {
	log *slog.Logger
	jg  job.Group

	cfg config.Config

	db   *statedb.DB
	nads statedb.RWTable[tables.NetworkAttachmentDefinition]

	crdcl apiextclientv1.CustomResourceDefinitionInterface
	nadcl func(string) nadclientv1.NetworkAttachmentDefinitionInterface
}

func newNetworkAttachmentDefinitions(in struct {
	cell.In

	Log      *slog.Logger
	JobGroup job.Group

	Config config.Config

	DB   *statedb.DB
	NADs statedb.RWTable[tables.NetworkAttachmentDefinition]

	Client       client.Clientset
	MultusClient nadclientv1.K8sCniCncfIoV1Interface
}) (*NetworkAttachmentDefinitions, error) {
	reconciler := &NetworkAttachmentDefinitions{
		log:  in.Log,
		jg:   in.JobGroup,
		cfg:  in.Config,
		db:   in.DB,
		nads: in.NADs,
	}

	if !in.Config.EnabledWithNADIntegration() {
		return reconciler, nil
	}

	if !in.Client.IsEnabled() || in.MultusClient == nil {
		return nil, errors.New("private networks requires Kubernetes support to be enabled")
	}

	reconciler.crdcl = in.Client.ApiextensionsV1().CustomResourceDefinitions()
	reconciler.nadcl = in.MultusClient.NetworkAttachmentDefinitions
	return reconciler, nil
}

func (n *NetworkAttachmentDefinitions) registerK8sReflector() error {
	if !n.cfg.EnabledWithNADIntegration() {
		return nil
	}

	return k8s.RegisterReflector(n.jg, n.db, k8s.ReflectorConfig[tables.NetworkAttachmentDefinition]{
		Name:          "to-table",
		Table:         n.nads,
		ListerWatcher: utils.ListerWatcherFromTyped(n.nadcl(corev1.NamespaceAll)),

		// Validate that the NetworkAttachmentDefinition CRD is actually present
		// before attempting to watch the existing instances.
		CRDSync: n.newCRDSyncPromise(),

		Transform: func(txn statedb.ReadTxn, obj any) (tables.NetworkAttachmentDefinition, bool) {
			nad, ok := obj.(*nadv1.NetworkAttachmentDefinition)
			if !ok {
				return tables.NetworkAttachmentDefinition{}, false
			}

			var cfg tables.NADCNIConfig

			// Attempt to unmarshal the core CNI fields first, and proceed with
			// full unmarshaling only if the type is cilium-cni, to avoid possible
			// spurious warnings when trying to parse configs for other CNIs.
			if err := json.Unmarshal([]byte(nad.Spec.Config), &cfg.NADCNIConfigCore); err != nil {
				n.log.Warn("Failed to parse CNI configuration from NetworkAttachmentDefinition",
					logfields.Error, err,
					logfields.K8sNamespace, nad.GetNamespace(),
					logfields.Name, nad.GetName(),
				)
			}

			if cfg.Type == tables.NADCNIConfigTypeCilium {
				if err := json.Unmarshal([]byte(nad.Spec.Config), &cfg); err != nil {
					n.log.Warn("Failed to parse CNI configuration from NetworkAttachmentDefinition",
						logfields.Error, err,
						logfields.K8sNamespace, nad.GetNamespace(),
						logfields.Name, nad.GetName(),
					)
				}
			}

			return tables.NetworkAttachmentDefinition{
				NamespacedName: tables.NamespacedName{
					Namespace: nad.GetNamespace(),
					Name:      nad.GetName(),
				},

				Labels:          nad.GetLabels(),
				Annotations:     nad.GetAnnotations(),
				Managed:         nad.GetLabels()[managedByLabelKey] == managedByLabelVal,
				UID:             nad.GetUID(),
				ResourceVersion: nad.GetResourceVersion(),

				CNIConfig: cfg,
			}, true
		},
	})
}

func (n *NetworkAttachmentDefinitions) newCRDSyncPromise() promise.Promise[synced.CRDSync] {
	resolve, promise := promise.New[synced.CRDSync]()

	n.jg.Add(
		job.OneShot("wait-for-nad-crd", func(ctx context.Context, health cell.Health) error {
			health.OK("Checking if NetworkAttachmentDefinition CRD exists")
			_, err := n.crdcl.Get(ctx, nadv1.Resource("network-attachment-definitions").String(),
				metav1.GetOptions{})

			// We don't explicitly validate the CRD conditions, as the CRD is managed externally.
			if err == nil {
				resolve.Resolve(synced.CRDSync{})
				return nil
			}

			return fmt.Errorf("checking NetworkAttachmentDefinition CRD existence: %w", err)
		}, job.WithRetry(-1, &job.ExponentialBackoff{Min: 1 * time.Second, Max: 30 * time.Second})),
	)

	return promise
}

func newNADsClient(cfg config.Config, client client.Clientset) (nadclientv1.K8sCniCncfIoV1Interface, error) {
	if !cfg.EnabledWithNADIntegration() {
		return nil, nil
	}

	if !client.IsEnabled() {
		return nil, errors.New("private networks requires Kubernetes support to be enabled")
	}

	out, err := nadclient.NewForConfig(client.RestConfig())
	if err != nil {
		return nil, fmt.Errorf("unable to create network attachment definitions client: %w", err)
	}

	return out.K8sCniCncfIoV1(), nil
}
