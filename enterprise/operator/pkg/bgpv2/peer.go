// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bgpv2

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"k8s.io/apimachinery/pkg/api/meta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/option"
)

type peerConfigStatusReconciler struct {
	cs              k8s_client.Clientset
	secretNamespace string
	secretStore     resource.Store[*slim_core_v1.Secret]
	peerConfigStore resource.Store[*v1alpha1.IsovalentBGPPeerConfig]
}

type peerConfigStatusReconcilerIn struct {
	cell.In

	Clientset    k8s_client.Clientset
	Config       config.Config
	DaemonConfig *option.DaemonConfig
	JobGroup     job.Group

	SecretResource     resource.Resource[*slim_core_v1.Secret]
	PeerConfigResource resource.Resource[*v1alpha1.IsovalentBGPPeerConfig]
}

func registerPeerConfigStatusReconciler(in peerConfigStatusReconcilerIn) {
	if !in.Config.Enabled {
		return
	}

	u := &peerConfigStatusReconciler{
		cs:              in.Clientset,
		secretNamespace: in.DaemonConfig.BGPSecretsNamespace,
	}

	in.JobGroup.Add(job.OneShot(
		"peer-config-status-reconciler",
		func(ctx context.Context, health cell.Health) error {
			ss, err := in.SecretResource.Store(ctx)
			if err != nil {
				return err
			}
			u.secretStore = ss

			ps, err := in.PeerConfigResource.Store(ctx)
			if err != nil {
				return err
			}
			u.peerConfigStore = ps

			se := in.SecretResource.Events(ctx)
			pe := in.PeerConfigResource.Events(ctx)

			health.OK("Running")

			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case e, ok := <-se:
					if !ok {
						continue
					}
					if e.Kind == resource.Sync {
						e.Done(nil)
						continue
					}
					e.Done(u.handleSecret(ctx, e))
				case e, ok := <-pe:
					if !ok {
						continue
					}
					if e.Kind != resource.Upsert {
						e.Done(nil)
						continue
					}
					e.Done(u.reconcilePeerConfig(ctx, e.Object))
				}
			}
		},
	))
}

func (u *peerConfigStatusReconciler) reconcilePeerConfig(ctx context.Context, config *v1alpha1.IsovalentBGPPeerConfig) error {
	updateStatus := false

	authSecretMissing := u.authSecretMissing(config)

	if changed := u.updateMissingAuthSecretCondition(config, authSecretMissing); changed {
		updateStatus = true
	}

	slices.SortStableFunc(config.Status.Conditions, func(a, b meta_v1.Condition) int {
		return strings.Compare(a.Type, b.Type)
	})

	if updateStatus {
		if _, err := u.cs.IsovalentV1alpha1().IsovalentBGPPeerConfigs().UpdateStatus(ctx, config, meta_v1.UpdateOptions{}); err != nil {
			return err
		}
	}

	return nil
}

func (u *peerConfigStatusReconciler) authSecretMissing(c *v1alpha1.IsovalentBGPPeerConfig) bool {
	if c.Spec.AuthSecretRef == nil {
		return false
	}
	if _, exists, _ := u.secretStore.GetByKey(resource.Key{Namespace: u.secretNamespace, Name: *c.Spec.AuthSecretRef}); !exists {
		return true
	}
	return false
}

func (u *peerConfigStatusReconciler) updateMissingAuthSecretCondition(config *v1alpha1.IsovalentBGPPeerConfig, missing bool) bool {
	cond := meta_v1.Condition{
		Type:               v1alpha1.BGPPeerConfigConditionMissingAuthSecret,
		Status:             meta_v1.ConditionFalse,
		ObservedGeneration: config.Generation,
		LastTransitionTime: meta_v1.Now(),
		Reason:             "MissingAuthSecret",
	}
	if missing {
		cond.Status = meta_v1.ConditionTrue
		cond.Message = fmt.Sprintf("Referenced Auth Secret %q is missing", *config.Spec.AuthSecretRef)
	}
	return meta.SetStatusCondition(&config.Status.Conditions, cond)
}

func (u *peerConfigStatusReconciler) handleSecret(ctx context.Context, e resource.Event[*slim_core_v1.Secret]) error {
	// Reconcile all peer configs that reference this secret. This is a bit
	// inefficient but since we don't expect a large number of PeerConfigs
	// or Secret in the BGP Secret namespace, this is acceptable.
	for _, pc := range u.peerConfigStore.List() {
		if pc.Spec.AuthSecretRef == nil {
			continue
		}
		if *pc.Spec.AuthSecretRef != e.Key.Name {
			continue
		}
		if err := u.reconcilePeerConfig(ctx, pc); err != nil {
			return err
		}
	}
	return nil
}
