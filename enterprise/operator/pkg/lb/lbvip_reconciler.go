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
	"context"
	"fmt"
	"net/netip"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	ossannotation "github.com/cilium/cilium/pkg/annotation"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/shortener"
)

const (
	placeholderServicePrefix = "lbvip-"
)

type lbVIPReconciler struct {
	logger logrus.FieldLogger
	client client.Client
	scheme *runtime.Scheme
}

type lbVIPReconcilerParams struct {
	logger logrus.FieldLogger
	client client.Client
	scheme *runtime.Scheme
}

func newLBVIPReconciler(params lbVIPReconcilerParams) *lbVIPReconciler {
	return &lbVIPReconciler{
		logger: params.logger,
		client: params.client,
		scheme: params.scheme,
	}
}

func (r *lbVIPReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&isovalentv1alpha1.LBVIP{}).
		Owns(&corev1.Service{}).
		Complete(r)
}

func (r *lbVIPReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	scopedLog := r.logger.WithFields(logrus.Fields{
		logfields.Controller: "LBVIP",
		logfields.Resource:   req.NamespacedName,
	})

	scopedLog.Info("Reconciling LBVIP")

	lbvip := &isovalentv1alpha1.LBVIP{}
	if err := r.client.Get(ctx, req.NamespacedName, lbvip); err != nil {
		if !k8serrors.IsNotFound(err) {
			return controllerruntime.Fail(fmt.Errorf("failed to get LBVIP: %w", err))
		}
		// We don't need to delete placeholder service explicitly because
		// we set owner reference and it will be garbage collected by k8s.
		return controllerruntime.Success()
	}

	if lbvip.GetDeletionTimestamp() != nil {
		scopedLog.Debug("LBVIP is marked for deletion - waiting for actual deletion")
		return controllerruntime.Success()
	}

	if err := r.createOrUpdateResources(ctx, lbvip); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to create or update service: %w", err))
	}

	return controllerruntime.Success()
}

func (r *lbVIPReconciler) createOrUpdateResources(ctx context.Context, lbvip *isovalentv1alpha1.LBVIP) error {
	//
	// Reconcile LBVIP spec
	//

	// In this implementation, we leverage an existing LBIPAM to allocate
	// the VIP. However, it is not capable of allocating the VIP for the
	// resources other than Service. As a workaround, we create a
	// "placeholder" Service which doesn't have any endpoints and claim the
	// VIP through it.
	svcName := k8stypes.NamespacedName{
		Namespace: lbvip.Namespace,
		Name:      shortener.ShortenK8sResourceName(placeholderServicePrefix + lbvip.Name),
	}

	currentSvc := &corev1.Service{}
	if err := r.client.Get(ctx, svcName, currentSvc); err != nil {
		if !k8serrors.IsNotFound(err) {
			return fmt.Errorf("failed to get existing service: %w", err)
		}
	}

	desiredService := r.desiredService(svcName, lbvip)

	// Set owner reference and rely on k8s GC to clean up the placeholder
	// Service when the LBVIP is deleted.
	if err := controllerutil.SetControllerReference(lbvip, desiredService, r.scheme); err != nil {
		return fmt.Errorf("failed to set ownerreference on placeholder Service: %w", err)
	}

	// Commit the placeholder Service
	if err := r.createOrUpdateService(ctx, desiredService); err != nil {
		return fmt.Errorf("failed to create or update Service: %w", err)
	}

	//
	// Reconcile LBVIP status
	//

	// LBIPAM
	v4VIP, err := r.extractVIPsFromService(currentSvc)
	if err != nil {
		return fmt.Errorf("failed to extract VIP from service: %w", err)
	}

	// IPv4 VIP is not yet assigned. Skip this reconciliation round.
	if !v4VIP.IsValid() {
		return nil
	}

	// Update the LBVIP status with the assigned VIP
	lbvip.Status.Addresses.IPv4 = v4VIP.String()

	// Commit the LBVIP status
	if err := r.client.Status().Update(ctx, lbvip); err != nil {
		return fmt.Errorf("failed to update LBVIP status: %w", err)
	}

	return nil
}

func (r *lbVIPReconciler) desiredService(svcName k8stypes.NamespacedName, lbvip *isovalentv1alpha1.LBVIP) *corev1.Service {
	annotations := map[string]string{
		// Set the sharing key to the name of the LBVIP. LBFrontends
		// that refer to this LBVIP will generate the T1 Service with
		// the same sharing key.
		ossannotation.LBIPAMSharingKey: lbvip.Name,
	}
	if lbvip.Spec.IPv4Request != nil {
		// In case of static allocation, we set the ips annotation
		annotations[ossannotation.LBIPAMIPsKey] = *lbvip.Spec.IPv4Request
	}
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   svcName.Namespace,
			Name:        svcName.Name,
			Annotations: annotations,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{
				// Port number is a mandatory field. However,
				// once we reserve the port for this
				// placeholder Service, the actual T1 services
				// sharing the VIP cannot use that port number.
				// Thus, we try to use a port number that is
				// not commonly used. Port number 1 is TCPMUX,
				// which the original RFC is already marked as
				// historic by IETF.
				{Port: 1},
			},
		},
	}
}

// TODO: Deduplicate this function with the one in lbFrontendReconciler
func (r *lbVIPReconciler) createOrUpdateService(ctx context.Context, desiredService *corev1.Service) error {
	svc := desiredService.DeepCopy()

	result, err := controllerutil.CreateOrUpdate(ctx, r.client, svc, func() error {
		svc.Spec = desiredService.Spec
		svc.OwnerReferences = desiredService.OwnerReferences
		svc.Annotations = desiredService.Annotations
		svc.Labels = desiredService.Labels

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or update Service: %w", err)
	}

	r.logger.Debugf("Service %s has been %s", client.ObjectKeyFromObject(svc), result)

	return nil
}

func (r *lbVIPReconciler) extractVIPsFromService(svc *corev1.Service) (netip.Addr, error) {
	// The VIP is not yet assigned. Skip the reconciliation.
	if len(svc.Status.LoadBalancer.Ingress) == 0 {
		return netip.Addr{}, nil
	}

	// The service got more than one VIPs. This is unexpected.
	if len(svc.Status.LoadBalancer.Ingress) > 1 {
		return netip.Addr{}, fmt.Errorf("service has more than one VIP assigned")
	}

	// The VIP is assigned. Parse it.
	v4Addr, err := netip.ParseAddr(svc.Status.LoadBalancer.Ingress[0].IP)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to parse VIP: %w", err)
	}

	// Currently, we only support IPv4 VIP. Check it.
	if !v4Addr.Is4() {
		return netip.Addr{}, fmt.Errorf("VIP is not an IPv4 address")
	}

	return v4Addr, nil
}
