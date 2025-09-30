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
	"log/slog"
	"net/netip"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ceeannotation "github.com/cilium/cilium/enterprise/pkg/annotation"
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
	logger *slog.Logger
	client client.Client
	scheme *runtime.Scheme
	config lbVIPReconcilerConfig
}

type lbVIPReconcilerConfig struct {
	ipFamilies reconcilerIPFamilyConfig
}

type reconcilerIPFamilyConfig struct {
	EnableIPv4 bool
	EnableIPv6 bool
}

func newLBVIPReconciler(logger *slog.Logger,
	client client.Client,
	scheme *runtime.Scheme,
	config lbVIPReconcilerConfig,
) *lbVIPReconciler {
	return &lbVIPReconciler{
		logger: logger,
		client: client,
		scheme: scheme,
		config: config,
	}
}

func (r *lbVIPReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&isovalentv1alpha1.LBVIP{}).
		Owns(&corev1.Service{}).
		Complete(r)
}

func (r *lbVIPReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	scopedLog := r.logger.With(
		logfields.Controller, "LBVIP",
		logfields.Resource, req.NamespacedName,
	)

	scopedLog.Info("Reconciling LBVIP")

	lbvip := &isovalentv1alpha1.LBVIP{}
	if err := r.client.Get(ctx, req.NamespacedName, lbvip); err != nil {
		if !k8serrors.IsNotFound(err) {
			return controllerruntime.Fail(fmt.Errorf("failed to get LBVIP: %w", err))
		}

		scopedLog.Debug("LBVIP not found - assuming it has been deleted")

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

	// delete service if ip family changed (to prevent that current clusterip doesn't match new ipfamily)
	if currentSvc.Name != "" && !slices.Equal(currentSvc.Spec.IPFamilies, desiredService.Spec.IPFamilies) {
		if err := r.client.Delete(ctx, currentSvc); err != nil {
			return fmt.Errorf("failed to delete Service due to ipfamily changes: %w", err)
		}
	}

	// Commit the placeholder Service
	if err := r.createOrUpdateService(ctx, desiredService); err != nil {
		return fmt.Errorf("failed to create or update Service: %w", err)
	}

	//
	// Reconcile LBVIP status
	//

	// LBIPAM
	v4VIP, v6VIP, err := r.extractVIPsFromService(currentSvc)
	if err != nil {
		return fmt.Errorf("failed to extract VIP from service: %w", err)
	}

	// IPv4 VIP is not yet assigned. Skip this reconciliation round.
	if v4VIP.IsValid() {
		// Update the LBVIP status with the assigned VIP
		lbvip.Status.Addresses.IPv4 = ptr.To(v4VIP.String())
	} else {
		// Otherwise, clear the VIP (possible when users change the requested IP)
		lbvip.Status.Addresses.IPv4 = nil
	}

	// IPv6 VIP is not yet assigned. Skip this reconciliation round.
	if v6VIP.IsValid() {
		// Update the LBVIP status with the assigned VIP
		lbvip.Status.Addresses.IPv6 = ptr.To(v6VIP.String())
	} else {
		// Otherwise, clear the VIP (possible when users change the requested IP)
		lbvip.Status.Addresses.IPv6 = nil
	}

	// Update the LBVIP status with the conditions
	lbvip.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeIPAddressAllocated, r.extractConditionsFromService(lbvip, currentSvc))
	lbvip.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeIPFamily, r.ipFamilyCondition(lbvip))

	lbvip.UpdateResourceStatus()

	// Commit the LBVIP status
	if err := r.client.Status().Update(ctx, lbvip); err != nil {
		return fmt.Errorf("failed to update LBVIP status: %w", err)
	}

	return nil
}

func buildLBIPAMIPString(ips ...*string) string {
	resolvedStrings := []string{}

	for _, ipRef := range ips {
		if ipRef != nil {
			resolvedStrings = append(resolvedStrings, *ipRef)
		}
	}

	return strings.Join(resolvedStrings, ",")
}

func (r *lbVIPReconciler) desiredService(svcName k8stypes.NamespacedName, lbvip *isovalentv1alpha1.LBVIP) *corev1.Service {
	annotations := map[string]string{
		// Set the sharing key to the name of the LBVIP. LBServices
		// that refer to this LBVIP will generate the T1 Service with
		// the same sharing key.
		ossannotation.LBIPAMSharingKey: lbvip.Name,

		// Don't advertise this Service with BGP. The actual
		// advertisement will be done with the T1 Services.
		ceeannotation.ServiceNoAdvertisement: "true",

		// don't expose the placeholder Service on any node
		ossannotation.ServiceNodeSelectorExposure: "service.cilium.io/node=never",
	}

	if lbvip.Spec.IPv4Request != nil || lbvip.Spec.IPv6Request != nil {
		annotations[ossannotation.LBIPAMIPsKey] = buildLBIPAMIPString(lbvip.Spec.IPv4Request, lbvip.Spec.IPv6Request)
	}

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: svcName.Namespace,
			Name:      svcName.Name,
			Labels: map[string]string{
				"loadbalancer.isovalent.com/vip-name": lbvip.Name,
			},
			Annotations: annotations,
		},
		Spec: corev1.ServiceSpec{
			Type:                          corev1.ServiceTypeLoadBalancer,
			AllocateLoadBalancerNodePorts: ptr.To(false),
			IPFamilies:                    getServiceIPFamilies(getIPFamily(lbvip)),
			IPFamilyPolicy:                getServiceIPFamilyPolicy(getIPFamily(lbvip)),
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

// TODO: Deduplicate this function with the one in lbServiceReconciler
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

	r.logger.Debug("Service has been update",
		logfields.Resource, client.ObjectKeyFromObject(svc),
		logfieldResult, result,
	)

	return nil
}

func (r *lbVIPReconciler) extractVIPsFromService(svc *corev1.Service) (netip.Addr, netip.Addr, error) {
	ipv4Addr := netip.Addr{}
	ipv6Addr := netip.Addr{}

	if len(svc.Status.LoadBalancer.Ingress) > 2 {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("service has more than two VIPs assigned")
	}

	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		addr, err := netip.ParseAddr(ingress.IP)
		if err != nil {
			return netip.Addr{}, netip.Addr{}, fmt.Errorf("failed to parse VIP: %w", err)
		}
		if addr.Is4() {
			ipv4Addr = addr
		} else {
			ipv6Addr = addr
		}
	}

	return ipv4Addr, ipv6Addr, nil
}

// Extract relevant conditions from the placeholder Service and convert them into LBVIP conditions
func (r *lbVIPReconciler) extractConditionsFromService(lbvip *isovalentv1alpha1.LBVIP, svc *corev1.Service) metav1.Condition {
	allocatedCondition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeIPAddressAllocated,
		Status:             metav1.ConditionUnknown,
		ObservedGeneration: lbvip.Generation,
		LastTransitionTime: metav1.Now(),
		Reason:             "Unknown",
		Message:            "Unknown",
	}

	configuredIPFamily := getIPFamily(lbvip)

	if (configuredIPFamily == ipFamilyDual || configuredIPFamily == ipFamilyV4) && lbvip.Status.Addresses.IPv4 == nil {
		allocatedCondition.Status = metav1.ConditionFalse
		allocatedCondition.Reason = isovalentv1alpha1.IPAddressAllocatedConditionReasonIPv4AddressNotAllocated
		allocatedCondition.Message = "IPv4 address hasn't been allocated yet"
	}

	if (configuredIPFamily == ipFamilyDual || configuredIPFamily == ipFamilyV6) && lbvip.Status.Addresses.IPv6 == nil {
		allocatedCondition.Status = metav1.ConditionFalse
		allocatedCondition.Reason = isovalentv1alpha1.IPAddressAllocatedConditionReasonIPv6AddressNotAllocated
		allocatedCondition.Message = "IPv6 address hasn't been allocated yet"
	}

	for _, cond := range svc.Status.Conditions {
		// Map LBIPAM conditions to LBVIP conditions
		if cond.Type == "cilium.io/IPAMRequestSatisfied" {
			switch cond.Status {
			case metav1.ConditionUnknown:
				// Still unknown. Do nothing.
			case metav1.ConditionTrue:
				allocatedCondition.Status = metav1.ConditionTrue
				allocatedCondition.Reason = "Allocated"
				allocatedCondition.Message = "IP address has been allocated"
			case metav1.ConditionFalse:
				allocatedCondition.Status = metav1.ConditionFalse
				switch cond.Reason {
				case "no_pool":
					allocatedCondition.Reason = isovalentv1alpha1.IPAddressAllocatedConditionReasonAddressNoPool
					allocatedCondition.Message = "No IP pool matches this VIP"
				case "out_of_ips":
					allocatedCondition.Reason = isovalentv1alpha1.IPAddressAllocatedConditionReasonAddressNoAvailableAddress
					allocatedCondition.Message = "No available address"
				case "already_allocated", "already_allocated_incompatible_service":
					allocatedCondition.Reason = isovalentv1alpha1.IPAddressAllocatedConditionReasonAddressAlreadyInUse
					allocatedCondition.Message = "Requested address is already in use"
				default:
					// Pass through the reason and message.
					// Assuming users will file an issue if
					// they see this message.
					allocatedCondition.Reason = "unexpected:" + cond.Reason
					allocatedCondition.Message = "Unexpected condition: " + cond.Message
				}
			}
		}
	}

	return allocatedCondition
}

func (r *lbVIPReconciler) ipFamilyCondition(lbvip *isovalentv1alpha1.LBVIP) metav1.Condition {
	condition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeIPFamily,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: lbvip.Generation,
		LastTransitionTime: metav1.Now(),
		Reason:             isovalentv1alpha1.IPFamilyValid,
		Message:            "Valid IP Families",
	}

	configuredIPFamily := getIPFamily(lbvip)

	if configuredIPFamily == ipFamilyDual && (!r.config.ipFamilies.EnableIPv4 || !r.config.ipFamilies.EnableIPv6) {
		condition.Status = metav1.ConditionFalse
		condition.Reason = isovalentv1alpha1.IPFamilyInvalid
		condition.Message = "IPFamily dual configured but either IPv4 or IPv6 is not enabled"
	}

	if configuredIPFamily == ipFamilyV4 && !r.config.ipFamilies.EnableIPv4 {
		condition.Status = metav1.ConditionFalse
		condition.Reason = isovalentv1alpha1.IPFamilyInvalid
		condition.Message = "IPFamily IPv4 configured but IPv4 is not enabled"
	}

	if configuredIPFamily == ipFamilyV6 && !r.config.ipFamilies.EnableIPv6 {
		condition.Status = metav1.ConditionFalse
		condition.Reason = isovalentv1alpha1.IPFamilyInvalid
		condition.Message = "IPFamily IPv6 configured but IPv6 is not enabled"
	}

	return condition
}
