//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package dnsresolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/cilium/workerpool"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	cilium_client_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
)

// reconciler watches for events related to each fqdn that is
// part of its fqdngroup and reconcile the related cidr group
// object accordingly.
type reconciler struct {
	logger *slog.Logger

	fqdnGroup    string
	fqdnGroupUID types.UID
	fqdns        []string

	clientset cilium_client_v2.CiliumCIDRGroupInterface
	ctrMgr    *controller.Manager

	store    notifier
	streamID streamID

	wp *workerpool.WorkerPool
}

func newReconciler(
	logger *slog.Logger,
	fqdnGroup string,
	fqdnGroupUID types.UID,
	fqdns []string,
	clientset cilium_client_v2.CiliumCIDRGroupInterface,
	ctrMgr *controller.Manager,
	store notifier,
) *reconciler {
	const logKey = "fromFqdnGroup"
	return &reconciler{
		logger:       logger.With(logKey, fqdnGroup),
		fqdnGroup:    fqdnGroup,
		fqdnGroupUID: fqdnGroupUID,
		fqdns:        fqdns,
		clientset:    clientset,
		ctrMgr:       ctrMgr,
		store:        store,
		wp:           workerpool.New(1),
	}
}

func (r *reconciler) start() error {
	name := "reconciler-" + r.fqdnGroup
	id, stream := r.store.events()
	r.streamID = id
	var cache []netip.Prefix
	return r.wp.Submit(
		name,
		func(_ context.Context) error {
			for range stream {
				prefixes := r.store.get(r.fqdns...)
				if cache != nil && slices.Equal(prefixes, cache) {
					continue
				}
				cache = prefixes

				cidrs := cidrs(cache)
				r.ctrMgr.UpdateController(
					r.fqdnGroup,
					controller.ControllerParams{
						Group: controller.NewGroup(name),
						DoFunc: func(ctx context.Context) error {
							return r.upsertCIDRGroup(ctx, cidrs)
						},
					},
				)
			}
			return nil
		},
	)
}

func (r *reconciler) stop() error {
	var errs []error
	if err := r.store.stop(r.streamID); err != nil {
		if errors.Is(err, errSubscriberNotFound) {
			r.logger.Error(
				"Reconciler could not be stopped due to missing underlying subscriber. There's no leak, but please report this behavior to the developers. Continuing with deletion.",
				logfields.Error, err,
			)
		} else {
			r.logger.Error(
				"Reconciler could not be stopped because it already was. There's no leak, but please report this behavior to the developers. Continuing with deletion.",
				logfields.Error, err,
			)
		}
		errs = append(errs, err)
	}
	if err := r.wp.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func cidrs(prefixes []netip.Prefix) []api.CIDR {
	cidrs := make([]api.CIDR, 0, len(prefixes))
	for _, prefix := range prefixes {
		cidrs = append(cidrs, api.CIDR(prefix.String()))
	}
	return cidrs
}

func (r *reconciler) upsertCIDRGroup(ctx context.Context, cidrs []api.CIDR) error {
	logger := r.logger.With(logfields.CIDRs, cidrs)

	logger.Debug("reconciling cidr group")

	var cidrsPatch []byte
	cidrsPatch, err := json.Marshal(
		[]k8s.JSONPatch{
			{
				OP:    "replace",
				Path:  "/spec/externalCIDRs",
				Value: cidrs,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("marshalling failed for CiliumCIDRGroup patch: %w", err)
	}

	if _, err := r.clientset.Patch(ctx, r.fqdnGroup, types.JSONPatchType, cidrsPatch, metav1.PatchOptions{}); err != nil {
		if k8sErrors.IsNotFound(err) {
			cidrGroup := &v2.CiliumCIDRGroup{
				TypeMeta: metav1.TypeMeta{
					APIVersion: v2.SchemeGroupVersion.String(),
					Kind:       v2.CCGKindDefinition,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: r.fqdnGroup,
					Labels: map[string]string{
						"app.kubernetes.io/part-of": "cilium",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: v1alpha1.SchemeGroupVersion.String(),
							Kind:       v1alpha1.IFGKindDefinition,
							Name:       r.fqdnGroup,
							UID:        r.fqdnGroupUID,
						},
					},
				},
				Spec: v2.CiliumCIDRGroupSpec{
					ExternalCIDRs: cidrs,
				},
			}
			if _, err := r.clientset.Create(ctx, cidrGroup, metav1.CreateOptions{}); err != nil {
				r.logger.Error(
					"Creation of CiliumCIDRGroup from the IsovalentFQDNGroup failed, will retry",
					logfields.Error, err,
				)
				return fmt.Errorf("create failed for CiliumCIDRGroup: %w", err)
			}
			return nil
		}
		r.logger.Error(
			"Patching of CiliumCIDRGroup with updated list of external CIDRs failed, will retry",
			logfields.Error, err,
		)
		return fmt.Errorf("patch failed for CiliumCIDRGroup: %w", err)
	}

	return nil
}
