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
	"slices"
	"strings"

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
	ossannotation "github.com/cilium/cilium/pkg/annotation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/addressing"
)

const (
	lbServiceVIPIndexName        = ".spec.vipRef.name"
	lbServiceBackendIndexName    = ".spec.routes.http.backend"
	lbServiceTlsSecretsIndexName = ".spec.tls.secrets" // TLS Certificates & Validation secrets
)

type lbServiceReconciler struct {
	logger       *slog.Logger
	client       client.Client
	scheme       *runtime.Scheme
	nodeSource   *ciliumNodeSource
	ingestor     *ingestor
	t1Translator *lbServiceT1Translator
	t2Translator *lbServiceT2Translator
}

type reconcilerConfig struct {
	SecretsNamespace    string
	ServerName          string
	AccessLog           reconcilerAccesslogConfig
	RequestID           reconcilerRequestIDConfig
	T1T2HealthCheck     reconcilerT1T2HealthCheckConfig
	OriginalIPDetection reconcilerOriginalIPDetectionConfig
}

type reconcilerAccesslogConfig struct {
	EnableStdOut   bool
	FilePath       string
	EnableHC       bool
	EnableTCP      bool
	FormatHC       string
	JSONFormatHC   string
	FormatTCP      string
	JSONFormatTCP  string
	FormatTLS      string
	JSONFormatTLS  string
	FormatHTTP     string
	JSONFormatHTTP string
}

type reconcilerRequestIDConfig struct {
	Generate bool
	Preserve bool
	Response bool
}

type reconcilerT1T2HealthCheckConfig struct {
	T1ProbeTimeoutSeconds              uint
	T1ProbeHttpPath                    string
	T1ProbeHttpMethod                  string
	T1ProbeHttpUserAgentPrefix         string
	T2ProbeMinHealthyBackendPercentage uint
}

type reconcilerOriginalIPDetectionConfig struct {
	UseRemoteAddress  bool
	XffNumTrustedHops uint
}

func newLbServiceReconciler(logger *slog.Logger, client client.Client, scheme *runtime.Scheme, nodeSource *ciliumNodeSource, ingestor *ingestor, t1Translator *lbServiceT1Translator, t2Translator *lbServiceT2Translator) *lbServiceReconciler {
	return &lbServiceReconciler{
		logger:       logger,
		client:       client,
		scheme:       scheme,
		nodeSource:   nodeSource,
		ingestor:     ingestor,
		t1Translator: t1Translator,
		t2Translator: t2Translator,
	}
}

// SetupWithManager sets up the controller with the Manager and configures
// the different watches. All the watcher trigger a reconciliation.
func (r *lbServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	for indexName, indexerFunc := range map[string]client.IndexerFunc{
		lbServiceVIPIndexName: func(rawObj client.Object) []string {
			return rawObj.(*isovalentv1alpha1.LBService).AllReferencedVIPNames()
		},
		lbServiceBackendIndexName: func(rawObj client.Object) []string {
			return rawObj.(*isovalentv1alpha1.LBService).AllReferencedBackendNames()
		},
		lbServiceTlsSecretsIndexName: func(rawObj client.Object) []string {
			return rawObj.(*isovalentv1alpha1.LBService).AllReferencedSecretNames()
		},
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
		// CiliumNode changes should trigger a reconciliation of all LBServices
		WatchesRawSource(r.nodeSource.ToSource(r.enqueueAllLBServices())).
		Complete(r)
}

// Reconcile implements the main reconciliation loop that gets triggered whenever a LBService resource or a related resource changes.
func (r *lbServiceReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	scopedLog := r.logger.With(
		logfields.Controller, "LBService",
		logfields.Resource, req.NamespacedName,
	)

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

	if err := r.reconcileResources(ctx, lb); err != nil {
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

	lb.UpdateResourceStatus()

	// Update the status of LBService
	if err := r.client.Status().Update(ctx, lb); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update LBService status: %w", err))
	}

	return controllerruntime.Success()
}

func (r *lbServiceReconciler) reconcileResources(ctx context.Context, lbsvc *isovalentv1alpha1.LBService) error {
	//
	// Load dependent resources that have relevant input for the model
	//

	t1NodeIPs, err := r.loadNodeAddressesByType(ctx, lbNodeTypeT1)
	if err != nil {
		return fmt.Errorf("failed to retrieve T1 node ips: %w", err)
	}

	t2NodeIPs, err := r.loadNodeAddressesByType(ctx, lbNodeTypeT2)
	if err != nil {
		return fmt.Errorf("failed to retrieve T2 node ips: %w", err)
	}

	// Try loading referenced LBVIP
	// -> vip can be nil
	vip, err := r.loadVIP(ctx, lbsvc)
	if err != nil {
		return fmt.Errorf("failed to load referenced LBVIP: %w", err)
	}

	r.updateVIPInStatus(lbsvc, vip)

	// Try loading any existing T1 K8s Service from a previous reconciliation as this might contain the IP that has been allocated by LB IPAM
	// -> existingT1K8sService can be nil
	existingT1K8sService, err := r.loadT1Service(ctx, lbsvc)
	if err != nil {
		return fmt.Errorf("failed to load existing T1 k8s service: %w", err)
	}

	// Try loading referenced LBBackends (in same namespace)
	backends, missingBackends, err := r.loadBackends(ctx, lbsvc)
	if err != nil {
		return fmt.Errorf("failed to load referenced backends: %w", err)
	}

	r.updateBackendExistenceInStatus(lbsvc, missingBackends)
	r.updateBackendCompatibilityInStatus(lbsvc, backends)

	// Try loading referenced TLS Secrets (in same namespace) to update the status accordingly
	referencedSecrets, missingSecrets, err := r.loadTLSSecrets(ctx, lbsvc)
	if err != nil {
		return fmt.Errorf("failed to load referenced TLS secrets: %w", err)
	}

	r.updateSecretExistenceInStatus(lbsvc, missingSecrets)
	r.updateSecretCompatibilityInStatus(lbsvc, referencedSecrets)

	//
	// Translate into internal model
	//

	model := r.ingestor.ingest(vip, lbsvc, backends, existingT1K8sService, t1NodeIPs, t2NodeIPs, referencedSecrets)

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
	desiredT1Service := r.t1Translator.DesiredService(model)
	desiredT1Endpoints := r.t1Translator.DesiredEndpoints(model)

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

	// Stop reconciliation if T1-only, T1 service is not available yet or is not able to bind
	// to the VIP (e.g. due to port clash with another service on the same VIP).
	// In this case any existing CEC gets deleted too. We don't delete Services & Endpoints
	// as this would result in a loop when the same services is created in the next
	// reconciliation.
	// Creating/Updating the T1 Service will trigger an additional reconciliation.
	if !model.vip.bindStatus.serviceExists || !model.vip.bindStatus.bindSuccessful || model.isTCPProxyT1OnlyMode() || model.isUDPProxyT1OnlyMode() {
		if err = r.ensureCECDeleted(ctx, model); err != nil {
			return fmt.Errorf("failed to ensure CEC is deleted: %w", err)
		}
		return nil
	}

	// Build desired resources
	desiredT2CiliumEnvoyConfig, err := r.t2Translator.DesiredCiliumEnvoyConfig(model)
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

	allReferencedBackendNames := lbsvc.AllReferencedBackendNames()

	for _, bName := range allReferencedBackendNames {
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

func (r *lbServiceReconciler) loadTLSSecrets(ctx context.Context, lbsvc *isovalentv1alpha1.LBService) (map[string]*corev1.Secret, []string, error) {
	missingSecrets := []string{}
	secretMap := map[string]*corev1.Secret{}

	// TLS Certs
	allReferencedSecretNames := lbsvc.AllReferencedSecretNames()

	for _, secretName := range allReferencedSecretNames {
		s := &corev1.Secret{}
		if err := r.client.Get(ctx, types.NamespacedName{Namespace: lbsvc.Namespace, Name: secretName}, s); err != nil {
			if !k8serrors.IsNotFound(err) {
				return nil, nil, fmt.Errorf("failed to get referenced TLS Secret: %w", err)
			}

			// Continue reconciliation if TLS Secrets don't exist (yet).
			// But keep track of them to report in log and status later on.
			// Once the missing referenced backends gets created it will trigger a reconciliation
			missingSecrets = append(missingSecrets, secretName)
			continue
		}

		secretMap[secretName] = s
	}

	return secretMap, missingSecrets, nil
}

func (r *lbServiceReconciler) loadT1Service(ctx context.Context, lbsvc *isovalentv1alpha1.LBService) (*corev1.Service, error) {
	svc := &corev1.Service{}
	if err := r.client.Get(ctx, types.NamespacedName{Namespace: lbsvc.Namespace, Name: getOwningResourceName(lbsvc.Name)}, svc); err != nil {
		if !k8serrors.IsNotFound(err) {
			return nil, err
		}

		// Continue if not found
		return nil, nil
	}

	return svc, nil
}

func (r *lbServiceReconciler) loadNodeAddressesByType(ctx context.Context, nodeType string) ([]string, error) {
	nodeStore, err := r.nodeSource.Store(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get node store: %w", err)
	}

	nodeIPs := []string{}

	allNodes := nodeStore.List()
	for _, cn := range allNodes {
		if v := cn.Labels[ossannotation.ServiceNodeExposure]; v == nodeType {
			var nodeIP string
			for _, addr := range cn.Spec.Addresses {
				if addr.Type == addressing.NodeInternalIP {
					nodeIP = addr.IP
					break
				}
			}
			if nodeIP == "" {
				r.logger.Warn("Could not find InternalIP for CiliumNode",
					logfields.Resource, cn.Name,
					"nodeType", nodeType,
				)
				continue
			}
			nodeIPs = append(nodeIPs, nodeIP)
		}
	}

	slices.Sort(nodeIPs)
	return nodeIPs, nil
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

	r.logger.Debug("Service has been updated",
		logfields.Resource, client.ObjectKeyFromObject(svc),
		"result", result,
	)

	return nil
}

func (r *lbServiceReconciler) ensureServiceDeleted(ctx context.Context, model *lbService) error {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: model.namespace,
			Name:      model.getOwningResourceName(),
		},
	}
	if err := r.client.Delete(ctx, svc); err != nil {
		if !k8serrors.IsNotFound(err) {
			return err
		}
		// Service does not exist, which is fine
	}
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

		r.logger.Debug("Endpoints has been updated",
			logfields.Resource, client.ObjectKeyFromObject(ep),
			"result", result,
		)
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

	r.logger.Debug("Endpoints has been deleted due to not having a single address",
		logfields.Resource, client.ObjectKeyFromObject(desiredEndpoints),
	)

	return nil
}

func (r *lbServiceReconciler) ensureEndpointsDeleted(ctx context.Context, model *lbService) error {
	ep := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: model.namespace,
			Name:      model.getOwningResourceName(),
		},
	}
	if err := r.client.Delete(ctx, ep); err != nil {
		if !k8serrors.IsNotFound(err) {
			return err
		}
		// Endpoints does not exist, which is fine
	}
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

	r.logger.Debug("CiliumEnvoyConfig has been updated",
		logfields.Resource, client.ObjectKeyFromObject(cec),
		"result", result,
	)

	return nil
}

func (r *lbServiceReconciler) ensureCECDeleted(ctx context.Context, model *lbService) error {
	cec := &ciliumv2.CiliumEnvoyConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: model.namespace,
			Name:      model.getOwningResourceName(),
		},
	}
	if err := r.client.Delete(ctx, cec); err != nil {
		if !k8serrors.IsNotFound(err) {
			return err
		}
		// CEC does not exist, which is fine
	}
	return nil
}

func (r *lbServiceReconciler) enqueueReferencingLBServicesByIndex(indexName string) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		lbList := isovalentv1alpha1.LBServiceList{}

		listOps := &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexName, obj.GetName()),
			Namespace:     obj.GetNamespace(),
		}

		if err := r.client.List(ctx, &lbList, listOps); err != nil {
			r.logger.Warn("Failed to list LBServices", logfields.Error, err)
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
			r.logger.Warn("Failed to list LBServices", logfields.Error, err)
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

	var assignedIPv4 *string

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

	lbsvc.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeIPAssigned, ipAssignedCondition)
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

	lbsvc.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeVIPExist, vipExistsCondition)
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

	lbsvc.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeBackendsExist, backendsExistCondition)
}

func (r *lbServiceReconciler) updateBackendCompatibilityInStatus(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) {
	backendsCompatibleCondition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeBackendsCompatible,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.BackendsCompatibleConditionReasonAllBackendsCompatible,
		Message:            "All referenced backends are compatible",
		ObservedGeneration: lbsvc.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	incompatibleBackendMessages := []string{}

	incompatibleBackendMessages = append(incompatibleBackendMessages, r.getIncompatiblePersistentBackendLBAlgorithms(lbsvc, backends)...)
	incompatibleBackendMessages = append(incompatibleBackendMessages, r.getIncompatibleT1MultipleBackendPorts(lbsvc, backends)...)
	incompatibleBackendMessages = append(incompatibleBackendMessages, r.getInvalidBackends(backends)...)
	incompatibleBackendMessages = append(incompatibleBackendMessages, r.getIncompatibleProxyProtocol(lbsvc, backends)...)

	if len(incompatibleBackendMessages) > 0 {
		backendsCompatibleCondition.Status = metav1.ConditionFalse
		backendsCompatibleCondition.Reason = isovalentv1alpha1.BackendsCompatibleConditionReasonIncompatibleBackends
		backendsCompatibleCondition.Message = strings.Join(incompatibleBackendMessages, "\n")
	}

	lbsvc.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeBackendsCompatible, backendsCompatibleCondition)
}

func (*lbServiceReconciler) getIncompatiblePersistentBackendLBAlgorithms(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) []string {
	incompatibleBackendMessages := []string{}

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
	case lbsvc.Spec.Applications.TCPProxy != nil:
		for _, r := range lbsvc.Spec.Applications.TCPProxy.Routes {
			if r.PersistentBackend != nil {
				backendsUsedForPersistentBackend[r.BackendRef.Name] = struct{}{}
			}
		}
	}

	// if the 'persistentBackend' property is added to udpProxy,
	// then fix the implementation here

	for b := range backendsUsedForPersistentBackend {
		for _, configuredBackend := range backends {
			if b == configuredBackend.Name && (configuredBackend.Spec.Loadbalancing == nil || configuredBackend.Spec.Loadbalancing.Algorithm.ConsistentHashing == nil) {
				incompatibleBackendMessages = append(incompatibleBackendMessages, fmt.Sprintf("Backend %q is incompatible: Configured \"persistentBackend\" without LB algorithm \"consistentHashing\"", b))
			}
		}
	}

	return incompatibleBackendMessages
}

func (*lbServiceReconciler) getIncompatibleT1MultipleBackendPorts(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) []string {
	incompatibleBackendMessages := []string{}

	backendsUsedAsT1OnlyBackend := map[string]struct{}{}

	if lbsvc.Spec.Applications.TCPProxy != nil && (lbsvc.Spec.Applications.TCPProxy.ForceMode == nil ||
		*lbsvc.Spec.Applications.TCPProxy.ForceMode == isovalentv1alpha1.LBTCPProxyForceModeT1 ||
		*lbsvc.Spec.Applications.TCPProxy.ForceMode == isovalentv1alpha1.LBTCPProxyForceModeAuto) { // TODO: remove auto from condition once we support T2 proxy

		for _, t1r := range lbsvc.Spec.Applications.TCPProxy.Routes {
			backendsUsedAsT1OnlyBackend[t1r.BackendRef.Name] = struct{}{}
		}
	} else if lbsvc.Spec.Applications.UDPProxy != nil && (lbsvc.Spec.Applications.UDPProxy.ForceMode == nil ||
		*lbsvc.Spec.Applications.UDPProxy.ForceMode == isovalentv1alpha1.LBUDPProxyForceModeT1 ||
		*lbsvc.Spec.Applications.UDPProxy.ForceMode == isovalentv1alpha1.LBUDPProxyForceModeAuto) { // TODO: remove auto from condition once we support T2 proxy

		for _, t1r := range lbsvc.Spec.Applications.UDPProxy.Routes {
			backendsUsedAsT1OnlyBackend[t1r.BackendRef.Name] = struct{}{}
		}
	}

	for b := range backendsUsedAsT1OnlyBackend {
		for _, configuredBackend := range backends {
			if b == configuredBackend.Name {
				port := int32(0)

				for _, be := range configuredBackend.Spec.Backends {
					if port == 0 {
						port = be.Port
					}
					if port != be.Port {
						incompatibleBackendMessages = append(incompatibleBackendMessages, fmt.Sprintf("Backend %q is incompatible: T1 only service does not support backends with different ports", b))
						break
					}
				}
			}
		}
	}

	return incompatibleBackendMessages
}

func (*lbServiceReconciler) getInvalidBackends(backends []*isovalentv1alpha1.LBBackendPool) []string {
	invalidBackendMessages := []string{}

	for _, b := range backends {
		condition := b.GetStatusCondition(isovalentv1alpha1.ConditionTypeBackendAccepted)

		if condition != nil && condition.Reason == isovalentv1alpha1.BackendAcceptedConditionReasonInvalid {
			invalidBackendMessages = append(invalidBackendMessages, fmt.Sprintf("Backend %q is invalid: %q", b.Name, condition.Message))
		}
	}

	return invalidBackendMessages
}

func (*lbServiceReconciler) getIncompatibleProxyProtocol(lbsvc *isovalentv1alpha1.LBService, backends []*isovalentv1alpha1.LBBackendPool) []string {
	invalidBackendMessages := []string{}

	if lbsvc.Spec.ProxyProtocolConfig == nil {
		for _, b := range backends {
			// This is to avoid DownstreamProtocolError for any request with ProxyProtocol to the given backend
			if b.Spec.ProxyProtocolConfig != nil {
				invalidBackendMessages = append(invalidBackendMessages, fmt.Sprintf("Backend %q is incompatible: ProxyProtocolConfig is not supported for LB services", b.Name))
			}
		}
	} else {
		for _, b := range backends {
			if b.Spec.ProxyProtocolConfig != nil && slices.Contains(lbsvc.Spec.ProxyProtocolConfig.DisallowedVersions, b.Spec.ProxyProtocolConfig.Version) {
				invalidBackendMessages = append(invalidBackendMessages, fmt.Sprintf("Backend %q is incompatible: ProxyProtocolConfig version %d is disallowed", b.Name, b.Spec.ProxyProtocolConfig.Version))
			}
		}
	}

	return invalidBackendMessages
}

func (*lbServiceReconciler) updateSecretExistenceInStatus(lbsvc *isovalentv1alpha1.LBService, missingSecrets []string) {
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

	lbsvc.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeSecretsExist, secretsExistCondition)
}

func (r *lbServiceReconciler) updateSecretCompatibilityInStatus(lbsvc *isovalentv1alpha1.LBService, referencedSecrets map[string]*corev1.Secret) {
	secretsCompatibleCondition := metav1.Condition{
		Type:               isovalentv1alpha1.ConditionTypeSecretsCompatible,
		Status:             metav1.ConditionTrue,
		Reason:             isovalentv1alpha1.SecretsCompatibleConditionReasonAllSecretsCompatible,
		Message:            "All referenced secrets are compatible",
		ObservedGeneration: lbsvc.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	}

	incompatibleSecretMessages := []string{}

	incompatibleSecretMessages = append(incompatibleSecretMessages, r.getIncompatibleSecretTypes(lbsvc, referencedSecrets)...)

	if len(incompatibleSecretMessages) > 0 {
		secretsCompatibleCondition.Status = metav1.ConditionFalse
		secretsCompatibleCondition.Reason = isovalentv1alpha1.SecretsCompatibleConditionReasonIncompatibleSecrets
		secretsCompatibleCondition.Message = strings.Join(incompatibleSecretMessages, "\n")
	}

	lbsvc.UpsertStatusCondition(isovalentv1alpha1.ConditionTypeSecretsCompatible, secretsCompatibleCondition)
}

func (r *lbServiceReconciler) getIncompatibleSecretTypes(lbsvc *isovalentv1alpha1.LBService, secretMap map[string]*corev1.Secret) []string {
	messages := []string{}

	for _, s := range lbsvc.AllReferencedTLSCertificateSecretNames() {
		secret, ok := secretMap[s]
		if !ok {
			continue
		}

		if secret.Type != corev1.SecretTypeTLS ||
			secret.Data[corev1.TLSCertKey] == nil || string(secret.Data[corev1.TLSCertKey]) == "" ||
			secret.Data[corev1.TLSPrivateKeyKey] == nil || string(secret.Data[corev1.TLSPrivateKeyKey]) == "" {

			messages = append(messages, fmt.Sprintf("Secret %q is incompatible: Referenced as TLS Certificate but not of type TLS and/or relevant data fields (%q, %q) missing", s, corev1.TLSCertKey, corev1.TLSPrivateKeyKey))
		}
	}

	for _, s := range lbsvc.AllReferencedTLSCACertValidationSecretNames() {
		secret, ok := secretMap[s]
		if !ok {
			continue
		}

		if secret.Type != corev1.SecretTypeOpaque ||
			secret.Data["ca.crt"] == nil || string(secret.Data["ca.crt"]) == "" {

			messages = append(messages, fmt.Sprintf("Secret %q is incompatible: Referenced as CA Certificate but not of type Opaque and/or relevant data fields (%q) missing", s, "ca.crt"))
		}
	}

	for _, s := range lbsvc.AllReferencedBasicAuthSecretNames() {
		secret, ok := secretMap[s]
		if !ok {
			continue
		}
		if secret.Type != corev1.SecretTypeOpaque {
			messages = append(messages, fmt.Sprintf("Secret %q is incompatible: Referenced as BasicAuth but not of type Opaque", s))
		}
	}

	return messages
}
