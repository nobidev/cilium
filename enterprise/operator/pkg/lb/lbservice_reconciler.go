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
	"slices"
	"strings"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	lbServiceVIPIndexName        = ".spec.vipRef.name"
	lbServiceBackendIndexName    = ".spec.routes.http.backend"
	lbServiceTlsSecretsIndexName = ".spec.tls.secrets" // TLS Certificates & Validation secrets
)

type lbServiceReconciler struct {
	logger     logrus.FieldLogger
	client     client.Client
	scheme     *runtime.Scheme
	nodeSource *ciliumNodeSource
	ingestor   *ingestor

	config reconcilerConfig
}

type reconcilerConfig struct {
	SecretsNamespace string
	ServerName       string
	AccessLog        reconcilerAccesslogConfig
	RequestID        reconcilerRequestIDConfig
	T1T2HealthCheck  reconcilerT1T2HealthCheckConfig
}

type reconcilerAccesslogConfig struct {
	EnableTCP  bool
	FormatTCP  string
	FormatHTTP string
	FormatTLS  string
	ExcludeHC  bool
}

type reconcilerRequestIDConfig struct {
	Generate bool
	Preserve bool
	Response bool
}

type reconcilerT1T2HealthCheckConfig struct {
	T1ProbeTimeoutSeconds              uint
	T2ProbeMinHealthyBackendPercentage uint
}

func newLbServiceReconciler(logger logrus.FieldLogger, client client.Client, scheme *runtime.Scheme, nodeSource *ciliumNodeSource, ingestor *ingestor, config reconcilerConfig) *lbServiceReconciler {
	return &lbServiceReconciler{
		logger:     logger,
		client:     client,
		scheme:     scheme,
		nodeSource: nodeSource,
		ingestor:   ingestor,

		config: config,
	}
}

// SetupWithManager sets up the controller with the Manager and configures
// the different watches. All the watcher trigger a reconciliation.
func (r *lbServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	for indexName, indexerFunc := range map[string]client.IndexerFunc{
		lbServiceVIPIndexName:        vipIndexerFunc,
		lbServiceBackendIndexName:    backendIndexerFunc,
		lbServiceTlsSecretsIndexName: tlsSecretIndexerFunc,
	} {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &isovalentv1alpha1.LBService{}, indexName, indexerFunc); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
		}
	}

	return ctrl.NewControllerManagedBy(mgr).
		// Watch for changed LBService resources (main resource)
		For(&isovalentv1alpha1.LBService{}).
		// Watch for changed LBVIP resources and trigger LBServices that reference the changed lbvip
		Watches(&isovalentv1alpha1.LBVIP{}, r.enqueueReferencingLBServicesByIndex(lbServiceVIPIndexName)).
		// Watch for changed LBBackend resources and trigger LBServices that reference the changed backend
		Watches(&isovalentv1alpha1.LBBackendPool{}, r.enqueueReferencingLBServicesByIndex(lbServiceBackendIndexName)).
		// Watch for changed Secrets resources and trigger LBServices that reference the changed Secret.
		// This is mainly to update the status. The actual content of the Secrets are getting transferred via sDS.
		Watches(&corev1.Secret{}, r.enqueueReferencingLBServicesByIndex(lbServiceTlsSecretsIndexName)).
		// T1 Service resource with OwnerReference to the LBService
		Owns(&corev1.Service{}).
		// T1 Endpoints resource with OwnerReference to the LBService
		Owns(&corev1.Endpoints{}).
		// T2 CiliumEnvoyConfig resource with OwnerReference to the LBService
		Owns(&ciliumv2.CiliumEnvoyConfig{}).
		// CiliumNode changes should trigger a reconciliation of all LBServices T1 Endpoints addresses (T2 nodes))
		WatchesRawSource(r.nodeSource.ToSource(r.enqueueAllLBServices())).
		Complete(r)
}

// Reconcile implements the main reconciliation loop that gets triggered whenever a LBService resource or a related resource changes.
func (r *lbServiceReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	scopedLog := r.logger.WithFields(logrus.Fields{
		logfields.Controller: "LBService",
		logfields.Resource:   req.NamespacedName,
	})

	scopedLog.Info("Reconciling LBService")
	lb := &isovalentv1alpha1.LBService{}
	if err := r.client.Get(ctx, req.NamespacedName, lb); err != nil {
		if !k8serrors.IsNotFound(err) {
			return controllerruntime.Fail(fmt.Errorf("failed to get LBService: %w", err))
		}

		// LBService has been deleted in the meantime
		return controllerruntime.Success()
	}

	// LBService gets deleted via foreground deletion (DeletionTimestamp set)
	// -> abort and wait for the actual deletion to trigger a reconcile
	if lb.GetDeletionTimestamp() != nil {
		scopedLog.Debug("LBService is marked for deletion - waiting for actual deletion")
		return controllerruntime.Success()
	}

	if err := r.reconcileResources(ctx, scopedLog, lb); err != nil {
		if k8serrors.IsForbidden(err) && k8serrors.HasStatusCause(err, corev1.NamespaceTerminatingCause) {
			// The creation of one of the resources failed because the
			// namespace is terminating. The LBService resource itself is also expected
			// to be marked for deletion, but we haven't yet received the
			// corresponding event, so let's not print an error message.
			scopedLog.Info("Aborting reconciliation because namespace is being terminated")
			return controllerruntime.Success()
		}

		return controllerruntime.Fail(fmt.Errorf("failed to reconcile LBService: %w", err))
	}

	// Update the status of LBService
	if err := r.client.Status().Update(ctx, lb); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update LBService status: %w", err))
	}

	return controllerruntime.Success()
}

func (r *lbServiceReconciler) reconcileResources(ctx context.Context, scopedLogger logrus.FieldLogger, lbsvc *isovalentv1alpha1.LBService) error {
	//
	// Load dependent resources that have relevant input for the model
	//

	// Try loading referenced LBVIP
	vip, err := r.loadVIP(ctx, lbsvc)
	if err != nil {
		return fmt.Errorf("failed to load referenced LBVIP: %w", err)
	}

	r.updateVIPInStatus(lbsvc, vip)

	// Try loading any existing T1 Service from a previous reconciliation as this might contain the IP that has been allocated by LB IPAM
	existingT1Service := &corev1.Service{}
	if err := r.client.Get(ctx, types.NamespacedName{Namespace: lbsvc.Namespace, Name: getOwningResourceName(lbsvc.Name)}, existingT1Service); err != nil {
		if !k8serrors.IsNotFound(err) {
			return fmt.Errorf("failed to get T1 Service: %w", err)
		}

		// Continue if not found
	}

	// Try loading referenced LBBackends (in same namespace)
	backends, missingBackends, err := r.loadBackends(ctx, lbsvc)
	if err != nil {
		return fmt.Errorf("failed to load referenced backends: %w", err)
	}

	if len(missingBackends) > 0 {
		scopedLogger.
			WithField("backends", missingBackends).
			Debug("Some referenced LBBackends don't exist")
	}

	r.updateBackendExistenceInStatus(lbsvc, missingBackends)
	r.updateBackendCompatibilityInStatus(lbsvc, backends)

	// Try loading referenced TLS Secrets (in same namespace) to update the status accordingly
	missingSecrets, err := r.getMissingTLSSecrets(ctx, lbsvc)
	if err != nil {
		return fmt.Errorf("failed to load referenced TLS secrets: %w", err)
	}

	if len(missingSecrets) > 0 {
		scopedLogger.
			WithField("secrets", missingSecrets).
			Debug("Some referenced TLS Secrets don't exist")
	}

	r.updateSecretsInStatus(lbsvc, missingSecrets)

	//
	// Translate into internal model
	//

	model, err := r.ingestor.ingest(vip, lbsvc, backends, existingT1Service)
	if err != nil {
		return fmt.Errorf("failed to ingest LBService into model: %w", err)
	}

	r.updateAssignedIpInStatus(model, lbsvc)
	// Stop reconciliation if assigned IP is not available yet. Also, we
	// should delete the T1 Service, Endpoints, and T2 CEC if they exist.
	// Otherwise, the BGP keeps advertise the stale VIP, DPlane keeps
	// handling the traffic towards the stable VIP, etc.
	if model.vip.assignedIPv4 == nil {
		if err = r.ensureServiceDeleted(ctx, model); err != nil {
			return fmt.Errorf("failed to ensure service is deleted: %w", err)
		}
		if err = r.ensureEndpointsDeleted(ctx, model); err != nil {
			return fmt.Errorf("failed to ensure endpoints is deleted: %w", err)
		}
		if err = r.ensureCECDeleted(ctx, model); err != nil {
			return fmt.Errorf("failed to ensure CEC is deleted: %w", err)
		}
		return nil
	}

	//
	// T1
	//

	// Build desired resources
	desiredT1Service := r.desiredService(model)

	// TODO: include in model?
	t2NodeIPs, err := r.getT2NodeAddresses(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve T2 node ips: %w", err)
	}

	desiredT1Endpoints, err := r.desiredEndpoints(model, t2NodeIPs)
	if err != nil {
		return err
	}

	// Set controlling ownerreferences
	if err := controllerutil.SetControllerReference(lbsvc, desiredT1Service, r.scheme); err != nil {
		return fmt.Errorf("failed to set ownerreference on T1 Service: %w", err)
	}

	if err := controllerutil.SetControllerReference(lbsvc, desiredT1Endpoints, r.scheme); err != nil {
		return fmt.Errorf("failed to set ownerreference on T1 Endpoints: %w", err)
	}

	// Create or update resources
	if err := r.createOrUpdateService(ctx, desiredT1Service); err != nil {
		return err
	}

	if err := r.createOrUpdateEndpoints(ctx, desiredT1Endpoints); err != nil {
		return err
	}

	//
	// T2
	//

	// Stop reconciliation if T1 service is not available yet or is not able to bind
	// to the VIP (e.g. due to port clash with another service on the same VIP).
	// In this case any existing CEC gets deleted too. We don't delete Services & Endpoints
	// as this would result in a loop when the same  services is created in the next
	// reconciliation.
	// Creating/Updating the T1 Service will trigger an additional reconciliation.
	if !model.vip.bindStatus.serviceExists || !model.vip.bindStatus.bindSuccessful {
		if err = r.ensureCECDeleted(ctx, model); err != nil {
			return fmt.Errorf("failed to ensure CEC is deleted: %w", err)
		}
		return nil
	}

	// Build desired resources
	desiredT2CiliumEnvoyConfig, err := r.desiredCiliumEnvoyConfig(model)
	if err != nil {
		return err
	}

	// Set controlling ownerreferences
	if err := controllerutil.SetControllerReference(lbsvc, desiredT2CiliumEnvoyConfig, r.scheme); err != nil {
		return fmt.Errorf("failed to set ownerreference on T2 CiliumEnvoyConfig: %w", err)
	}

	// Create or update resources
	if err := r.createOrUpdateCiliumEnvoyConfig(ctx, desiredT2CiliumEnvoyConfig); err != nil {
		return err
	}

	return nil
}

func (r *lbServiceReconciler) loadVIP(ctx context.Context, lbsvc *isovalentv1alpha1.LBService) (*isovalentv1alpha1.LBVIP, error) {
	vip := &isovalentv1alpha1.LBVIP{}
	if err := r.client.Get(ctx, types.NamespacedName{Namespace: lbsvc.Namespace, Name: lbsvc.Spec.VIPRef.Name}, vip); err != nil {
		if !k8serrors.IsNotFound(err) {
			return nil, err
		}

		// Continue if not found
		return nil, nil
	}

	return vip, nil
}

func (r *lbServiceReconciler) loadBackends(ctx context.Context, lbsvc *isovalentv1alpha1.LBService) ([]*isovalentv1alpha1.LBBackendPool, []string, error) {
	backends := []*isovalentv1alpha1.LBBackendPool{}
	missingBackends := []string{}

	backendNames := allBackendNames(lbsvc)

	for _, bName := range backendNames {
		b := &isovalentv1alpha1.LBBackendPool{}
		if err := r.client.Get(ctx, types.NamespacedName{Namespace: lbsvc.Namespace, Name: bName}, b); err != nil {
			if !k8serrors.IsNotFound(err) {
				return nil, nil, fmt.Errorf("failed to get referenced LBBackend: %w", err)
			}

			// Continue reconciliation if backends don't exist (yet).
			// But keep track of them to report in log and status later on.
			// Once the missing referenced backends gets created it will trigger a reconciliation
			missingBackends = append(missingBackends, bName)
			continue
		}

		backends = append(backends, b)
	}

	return backends, missingBackends, nil
}

func (r *lbServiceReconciler) getMissingTLSSecrets(ctx context.Context, lbsvc *isovalentv1alpha1.LBService) ([]string, error) {
	allReferencedSecretNames := allReferencedSecretNames(lbsvc)

	missingSecrets := []string{}

	for _, secretName := range allReferencedSecretNames {
		s := &corev1.Secret{}
		if err := r.client.Get(ctx, types.NamespacedName{Namespace: lbsvc.Namespace, Name: secretName}, s); err != nil {
			if !k8serrors.IsNotFound(err) {
				return nil, fmt.Errorf("failed to get referenced TLS Secret: %w", err)
			}

			// Continue reconciliation if TLS Secrets don't exist (yet).
			// But keep track of them to report in log and status later on.
			// Once the missing referenced backends gets created it will trigger a reconciliation
			missingSecrets = append(missingSecrets, secretName)
		}
	}

	return missingSecrets, nil
}

func (r *lbServiceReconciler) createOrUpdateService(ctx context.Context, desiredService *corev1.Service) error {
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

func (r *lbServiceReconciler) createOrUpdateEndpoints(ctx context.Context, desiredEndpoints *corev1.Endpoints) error {
	if len(desiredEndpoints.Subsets[0].Addresses) != 0 {
		ep := desiredEndpoints.DeepCopy()
		result, err := controllerutil.CreateOrUpdate(ctx, r.client, ep, func() error {
			ep.Subsets = desiredEndpoints.Subsets
			ep.OwnerReferences = desiredEndpoints.OwnerReferences
			ep.Annotations = desiredEndpoints.Annotations
			ep.Labels = desiredEndpoints.Labels

			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to create or update Endpoints: %w", err)
		}

		r.logger.Debugf("Endpoints %s has been %s", client.ObjectKeyFromObject(ep), result)
		return nil
	}

	// Delete invalid Endpoints resource due to zero addresses
	// Prevents following error: subsets[0]: Required value: must specify `addresses` or `notReadyAddresses
	if err := r.client.Delete(ctx, desiredEndpoints); err != nil {
		if !k8serrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete endpoint: %w", err)
		}

		return nil
	}

	r.logger.Debugf("Endpoints %s has been deleted due to not having a single address", client.ObjectKeyFromObject(desiredEndpoints))

	return nil
}

func (r *lbServiceReconciler) createOrUpdateCiliumEnvoyConfig(ctx context.Context, desiredCEC *ciliumv2.CiliumEnvoyConfig) error {
	cec := desiredCEC.DeepCopy()

	result, err := controllerutil.CreateOrUpdate(ctx, r.client, cec, func() error {
		cec.Spec = desiredCEC.Spec
		cec.OwnerReferences = desiredCEC.OwnerReferences
		cec.Annotations = desiredCEC.Annotations
		cec.Labels = desiredCEC.Labels

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or update CiliumEnvoyConfig: %w", err)
	}

	r.logger.Debugf("CiliumEnvoyConfig %s has been %s", client.ObjectKeyFromObject(cec), result)

	return nil
}

func vipIndexerFunc(rawObj client.Object) []string {
	// Extract the VIP reference
	lbService := rawObj.(*isovalentv1alpha1.LBService)

	if lbService.Spec.VIPRef.Name == "" {
		return nil
	}

	return []string{lbService.Spec.VIPRef.Name}
}

func backendIndexerFunc(rawObj client.Object) []string {
	// Extract the backend references
	lbService := rawObj.(*isovalentv1alpha1.LBService)

	return allBackendNames(lbService)
}

func allBackendNames(lbService *isovalentv1alpha1.LBService) []string {
	backends := []string{}

	if lbService.Spec.Applications.HTTPProxy != nil {
		for _, lr := range lbService.Spec.Applications.HTTPProxy.Routes {
			backends = append(backends, lr.BackendRef.Name)
		}
	}
	if lbService.Spec.Applications.HTTPSProxy != nil {
		for _, lr := range lbService.Spec.Applications.HTTPSProxy.Routes {
			backends = append(backends, lr.BackendRef.Name)
		}
	}
	if lbService.Spec.Applications.TLSPassthrough != nil {
		for _, lr := range lbService.Spec.Applications.TLSPassthrough.Routes {
			backends = append(backends, lr.BackendRef.Name)
		}
	}
	if lbService.Spec.Applications.TLSProxy != nil {
		for _, lr := range lbService.Spec.Applications.TLSProxy.Routes {
			backends = append(backends, lr.BackendRef.Name)
		}
	}
	slices.Sort(backends)
	return slices.Compact(backends)
}

func tlsSecretIndexerFunc(rawObj client.Object) []string {
	lbService := rawObj.(*isovalentv1alpha1.LBService)

	// Extract the TLS secret references
	return allReferencedSecretNames(lbService)
}

func allReferencedSecretNames(lbService *isovalentv1alpha1.LBService) []string {
	secretNames := []string{}

	if lbService.Spec.Applications.HTTPSProxy != nil {
		if lbService.Spec.Applications.HTTPSProxy.TLSConfig == nil {
			return secretNames
		}
		for _, c := range lbService.Spec.Applications.HTTPSProxy.TLSConfig.Certificates {
			secretNames = append(secretNames, c.SecretRef.Name)
		}
		if lbService.Spec.Applications.HTTPSProxy.TLSConfig.Validation != nil {
			secretNames = append(secretNames, lbService.Spec.Applications.HTTPSProxy.TLSConfig.Validation.SecretRef.Name)
		}
	}

	if lbService.Spec.Applications.TLSProxy != nil {
		if lbService.Spec.Applications.TLSProxy.TLSConfig == nil {
			return secretNames
		}
		for _, c := range lbService.Spec.Applications.TLSProxy.TLSConfig.Certificates {
			secretNames = append(secretNames, c.SecretRef.Name)
		}
		if lbService.Spec.Applications.TLSProxy.TLSConfig.Validation != nil {
			secretNames = append(secretNames, lbService.Spec.Applications.TLSProxy.TLSConfig.Validation.SecretRef.Name)
		}
	}

	slices.Sort(secretNames)
	return slices.Compact(secretNames)
}

func (r *lbServiceReconciler) enqueueReferencingLBServicesByIndex(indexName string) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		lbList := isovalentv1alpha1.LBServiceList{}

		listOps := &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexName, obj.GetName()),
			Namespace:     obj.GetNamespace(),
		}

		if err := r.client.List(ctx, &lbList, listOps); err != nil {
			r.logger.WithError(err).Warn("Failed to list LBServices")
			return nil
		}

		result := []reconcile.Request{}

		for _, i := range lbList.Items {
			result = append(result, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: i.Namespace,
					Name:      i.Name,
				},
			})
		}

		return result
	})
}

func (r *lbServiceReconciler) enqueueAllLBServices() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		lbList := isovalentv1alpha1.LBServiceList{}
		if err := r.client.List(ctx, &lbList); err != nil {
			r.logger.WithError(err).Warn("Failed to list LBServices")
			return nil
		}

		result := []reconcile.Request{}

		for _, i := range lbList.Items {
			result = append(result, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: i.Namespace,
					Name:      i.Name,
				},
			})
		}

		return result
	})
}

func (*lbServiceReconciler) updateAssignedIpInStatus(model *lbService, lbsvc *isovalentv1alpha1.LBService) {
	ipAssignedCondition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeIPAssigned,
		Status:             metav1.ConditionFalse,
		Reason:             isovalentv1alpha1.IPAssignedConditionReasonIPPending,
		Message:            "VIP pending",
		ObservedGeneration: lbsvc.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	var assignedIPv4 *string = nil

	if model.vip.bindStatus.serviceExists && !model.vip.bindStatus.bindSuccessful {
		ipAssignedCondition.Reason = isovalentv1alpha1.IPAssignedConditionReasonIPFailure
		ipAssignedCondition.Message = "Failed to bind to VIP: " + model.vip.bindStatus.bindIssue
	} else if model.vip.assignedIPv4 != nil {
		ipAssignedCondition.Status = metav1.ConditionTrue
		ipAssignedCondition.Reason = isovalentv1alpha1.IPAssignedConditionReasonIPAssigned
		ipAssignedCondition.Message = "VIP assigned"

		assignedIPv4 = model.vip.assignedIPv4
	}

	lbsvc.Status.Addresses.IPv4 = assignedIPv4

	upsertCondition(lbsvc, isovalentv1alpha1.ConditionTypeIPAssigned, ipAssignedCondition)
}

func (*lbServiceReconciler) updateVIPInStatus(lbsvc *isovalentv1alpha1.LBService, vip *isovalentv1alpha1.LBVIP) {
	vipExistsCondition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeVIPExist,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.VIPExistConditionReasonVIPExists,
		Message:            "Referenced VIP exist",
		ObservedGeneration: lbsvc.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	if vip == nil {
		vipExistsCondition.Status = metav1.ConditionFalse
		vipExistsCondition.Reason = isovalentv1alpha1.VIPExistConditionReasonVIPMissing
		vipExistsCondition.Message = fmt.Sprintf("Referenced VIP %v is missing", lbsvc.Spec.VIPRef.Name)
	}

	upsertCondition(lbsvc, isovalentv1alpha1.ConditionTypeVIPExist, vipExistsCondition)
}

func (*lbServiceReconciler) updateBackendExistenceInStatus(lbsvc *isovalentv1alpha1.LBService, missingBackends []string) {
	backendsExistCondition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeBackendsExist,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.BackendsExistConditionReasonAllBackendsExist,
		Message:            "All referenced backends exist",
		ObservedGeneration: lbsvc.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	if len(missingBackends) > 0 {
		backendsExistCondition.Status = metav1.ConditionFalse
		backendsExistCondition.Reason = isovalentv1alpha1.BackendsExistConditionReasonMissingBackends
		backendsExistCondition.Message = fmt.Sprintf("There are referenced backends that do not exist: %v", missingBackends)
	}

	upsertCondition(lbsvc, isovalentv1alpha1.ConditionTypeBackendsExist, backendsExistCondition)
}

func (*lbServiceReconciler) updateBackendCompatibilityInStatus(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) {
	backendsCompatibleCondition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeBackendsCompatible,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.BackendsCompatibleConditionReasonAllBackendsCompatible,
		Message:            "All referenced backends are compatible",
		ObservedGeneration: lbsvc.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	backendsUsedForPersistentBackend := map[string]struct{}{}

	switch {
	case lbsvc.Spec.Applications.HTTPProxy != nil:
		for _, r := range lbsvc.Spec.Applications.HTTPProxy.Routes {
			if r.PersistentBackend != nil {
				backendsUsedForPersistentBackend[r.BackendRef.Name] = struct{}{}
			}
		}
	case lbsvc.Spec.Applications.HTTPSProxy != nil:
		for _, r := range lbsvc.Spec.Applications.HTTPSProxy.Routes {
			if r.PersistentBackend != nil {
				backendsUsedForPersistentBackend[r.BackendRef.Name] = struct{}{}
			}
		}
	case lbsvc.Spec.Applications.TLSPassthrough != nil:
		for _, r := range lbsvc.Spec.Applications.TLSPassthrough.Routes {
			if r.PersistentBackend != nil {
				backendsUsedForPersistentBackend[r.BackendRef.Name] = struct{}{}
			}
		}
	case lbsvc.Spec.Applications.TLSProxy != nil:
		for _, r := range lbsvc.Spec.Applications.TLSProxy.Routes {
			if r.PersistentBackend != nil {
				backendsUsedForPersistentBackend[r.BackendRef.Name] = struct{}{}
			}
		}
	}

	hasIncompatibleBackends := false
	incompatibleBackends := []string{}

	for b := range backendsUsedForPersistentBackend {
		for _, configuredBackend := range backends {
			if b == configuredBackend.Name && (configuredBackend.Spec.Loadbalancing == nil || configuredBackend.Spec.Loadbalancing.Algorithm.ConsistentHashing == nil) {
				hasIncompatibleBackends = true
				incompatibleBackends = append(incompatibleBackends, fmt.Sprintf("Backend %q is incompatible: Configured \"persistentBackend\" without LB algorithm \"consistentHashing\"", b))
			}
		}
	}

	if hasIncompatibleBackends {
		backendsCompatibleCondition.Status = metav1.ConditionFalse
		backendsCompatibleCondition.Reason = isovalentv1alpha1.BackendsCompatibleConditionReasonIncompatibleBackends
		backendsCompatibleCondition.Message = strings.Join(incompatibleBackends, "\n")
	}

	upsertCondition(lbsvc, isovalentv1alpha1.ConditionTypeBackendsCompatible, backendsCompatibleCondition)
}

func (*lbServiceReconciler) updateSecretsInStatus(lbsvc *isovalentv1alpha1.LBService, missingSecrets []string) {
	secretsExistCondition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeSecretsExist,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.SecretsExistConditionReasonAllSecretsExist,
		Message:            "All referenced TLS secrets exist",
		ObservedGeneration: lbsvc.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	if len(missingSecrets) > 0 {
		secretsExistCondition.Status = metav1.ConditionFalse
		secretsExistCondition.Reason = isovalentv1alpha1.SecretsExistConditionReasonMissingSecrets
		secretsExistCondition.Message = fmt.Sprintf("There are referenced TLS secrets that do not exist: %v", missingSecrets)
	}

	upsertCondition(lbsvc, isovalentv1alpha1.ConditionTypeSecretsExist, secretsExistCondition)
}

func upsertCondition(lbsvc *isovalentv1alpha1.LBService, conditionType string, condition metav1.Condition) {
	conditionExists := false
	for i, c := range lbsvc.Status.Conditions {
		if c.Type == conditionType {
			if c.Status != condition.Status ||
				c.Reason != condition.Reason ||
				c.Message != condition.Message ||
				c.ObservedGeneration != condition.ObservedGeneration {
				// transition -> update condition
				lbsvc.Status.Conditions[i] = condition
			}
			conditionExists = true
			break
		}
	}

	if !conditionExists {
		lbsvc.Status.Conditions = append(lbsvc.Status.Conditions, condition)
	}
}
