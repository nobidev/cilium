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
	"github.com/cilium/stream"
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
	bfdProfileStore resource.Store[*v1alpha1.IsovalentBFDProfile]
	peerConfigStore resource.Store[*v1alpha1.IsovalentBGPPeerConfig]
}

type peerConfigStatusReconcilerIn struct {
	cell.In

	Clientset    k8s_client.Clientset
	Config       config.Config
	DaemonConfig *option.DaemonConfig
	JobGroup     job.Group

	SecretResource     resource.Resource[*slim_core_v1.Secret]
	BFDProfileResource resource.Resource[*v1alpha1.IsovalentBFDProfile]
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

			// BFDProfile is initialized conditionally. When BFD is
			// not enabled, it doesn't make sense to subscribe
			// BFDProfile. Use empty store and stucking events when
			// BFD is disabled (the Resource[T] is not provided).
			var be <-chan resource.Event[*v1alpha1.IsovalentBFDProfile]
			if in.BFDProfileResource != nil {
				bp, err := in.BFDProfileResource.Store(ctx)
				if err != nil {
					return err
				}
				u.bfdProfileStore = bp

				// Real events
				be = in.BFDProfileResource.Events(ctx)
			} else {
				// Dummy event channel. It will never produce any event.
				stuck := stream.Stuck[resource.Event[*v1alpha1.IsovalentBFDProfile]]()
				be = stream.ToChannel(ctx, stuck)
			}

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
				case e, ok := <-be:
					if !ok {
						continue
					}
					if e.Kind == resource.Sync {
						e.Done(nil)
						continue
					}
					e.Done(u.handleBFDProfile(ctx, e))
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
	bfdProfileMissing := u.bfdProfileMissing(config)

	if changed := u.updateMissingAuthSecretCondition(config, authSecretMissing); changed {
		updateStatus = true
	}
	if changed := u.updateMissingBFDProfileCondition(config, bfdProfileMissing); changed {
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

func (u *peerConfigStatusReconciler) bfdProfileMissing(c *v1alpha1.IsovalentBGPPeerConfig) bool {
	if u.bfdProfileStore == nil {
		// If BFD is disabled, always false.
		return false
	}
	if c.Spec.BFDProfileRef == nil {
		return false
	}
	if _, exists, _ := u.bfdProfileStore.GetByKey(resource.Key{Name: *c.Spec.BFDProfileRef}); !exists {
		return true
	}
	return false
}

func (u *peerConfigStatusReconciler) updateMissingBFDProfileCondition(config *v1alpha1.IsovalentBGPPeerConfig, missing bool) bool {
	cond := meta_v1.Condition{
		Type:               v1alpha1.BGPPeerConfigConditionMissingBFDProfile,
		Status:             meta_v1.ConditionFalse,
		ObservedGeneration: config.Generation,
		LastTransitionTime: meta_v1.Now(),
		Reason:             "MissingBFDProfile",
	}
	if missing {
		cond.Status = meta_v1.ConditionTrue
		cond.Message = fmt.Sprintf("Referenced BFP Profile %q is missing", *config.Spec.BFDProfileRef)
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

func (u *peerConfigStatusReconciler) handleBFDProfile(ctx context.Context, e resource.Event[*v1alpha1.IsovalentBFDProfile]) error {
	// Reconcile all peer configs that reference this BFDProfile. This is a bit
	// inefficient but since we don't expect a large number of PeerConfigs
	// or BFDProfile, this is acceptable.
	for _, pc := range u.peerConfigStore.List() {
		if pc.Spec.BFDProfileRef == nil {
			continue
		}
		if *pc.Spec.BFDProfileRef != e.Key.Name {
			continue
		}
		if err := u.reconcilePeerConfig(ctx, pc); err != nil {
			return err
		}
	}
	return nil
}
