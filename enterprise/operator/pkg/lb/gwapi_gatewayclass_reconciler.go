package lb

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	"time"

	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	k8syaml "sigs.k8s.io/yaml"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	configChecksumAnnotation       = "gateway.isovalent.io/config-checksum"
	gatewayClassConfigMapIndexName = ".spec.parametersRef"
	gatewayClassAcceptedMessage    = "Valid GatewayClass"
	gatewayClassNotAcceptedMessage = "Invalid GatewayClass"
	gatewayClass                   = "gatewayClass"
)

// gatewayClassReconciler reconciles a GatewayClass object
type gatewayClassReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	logger *slog.Logger
}

func newGatewayClassReconciler(mgr ctrl.Manager, logger *slog.Logger) *gatewayClassReconciler {
	return &gatewayClassReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		logger: logger,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *gatewayClassReconciler) SetupWithManager(mgr ctrl.Manager) error {

	for indexName, indexerFunc := range map[string]client.IndexerFunc{
		gatewayClassConfigMapIndexName: referencedConfig,
	} {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.GatewayClass{}, indexName, indexerFunc); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
		}
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.GatewayClass{}, builder.WithPredicates(predicate.NewPredicateFuncs(matchesControllerName(controllerName)))).
		Watches(&gatewayv1.GatewayClass{}, r.enqueueRequestForGatewayClassConfig()).
		Complete(r)
}

func (r *gatewayClassReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.logger.With(
		logfields.Controller, "gatewayclassILB",
		logfields.Resource, req.NamespacedName,
	)

	scopedLog.Info("Reconciling ILB GatewayClass")
	original := &gatewayv1.GatewayClass{}
	if err := r.Client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			return controllerruntime.Success()
		}
		return controllerruntime.Fail(err)
	}

	// Ignore deleted GatewayClass, this can happen when foregroundDeletion is enabled
	// The reconciliation loop will automatically kick off for related Gateway resources.
	if original.GetDeletionTimestamp() != nil {
		return controllerruntime.Success()
	}

	gwc := original.DeepCopy()

	if ref := gwc.Spec.ParametersRef; ref != nil {
		if !isParameterRefSupported(ref) {
			scopedLog.Error("Only CiliumGatewayClassConfig is supported for ParametersRef")
			setGatewayClassAccepted(gwc, false)
			if err := r.ensureStatus(ctx, gwc, original); err != nil {
				scopedLog.ErrorContext(ctx, "Failed to update GatewayClass status", logfields.Error, err)
				return controllerruntime.Fail(err)
			}
			return controllerruntime.Fail(nil)
		}

		if ref.Namespace == nil || ref.Name == "" {
			scopedLog.Error("ParametersRef must specify namespace and name")
			setGatewayClassAccepted(gwc, false)
			if err := r.ensureStatus(ctx, gwc, original); err != nil {
				scopedLog.ErrorContext(ctx, "Failed to update GatewayClass status", logfields.Error, err)
				return controllerruntime.Fail(err)
			}
			return controllerruntime.Fail(nil)
		}

		cgcc := &v2alpha1.CiliumGatewayClassConfig{}
		key := client.ObjectKey{
			Namespace: string(*ref.Namespace),
			Name:      ref.Name,
		}
		if err := r.Client.Get(ctx, key, cgcc); err != nil {
			setGatewayClassAccepted(gwc, false)
			if err := r.ensureStatus(ctx, gwc, original); err != nil {
				scopedLog.ErrorContext(ctx, "Failed to update GatewayClass status", logfields.Error, err)
				return controllerruntime.Fail(err)
			}
			return controllerruntime.Fail(err)
		}

		if gwc.Annotations == nil {
			gwc.Annotations = make(map[string]string)
		}
		gwc.Annotations[configChecksumAnnotation] = checksum(cgcc)

		if err := r.ensureResource(ctx, gwc, original); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to update GatewayClass", logfields.Error, err)
			return controllerruntime.Fail(err)
		}
	}

	setGatewayClassAccepted(gwc, true)
	//setGatewayClassSupportedFeatures(gwc)
	if err := r.ensureStatus(ctx, gwc, original); err != nil {
		scopedLog.ErrorContext(ctx, "Failed to update GatewayClass status", logfields.Error, err)
		return controllerruntime.Fail(err)
	}

	scopedLog.Info("Successfully reconciled GatewayClass")
	return controllerruntime.Success()
}
func (r *gatewayClassReconciler) ensureResource(ctx context.Context, gwc *gatewayv1.GatewayClass, original *gatewayv1.GatewayClass) error {
	return r.Client.Patch(ctx, gwc, client.MergeFrom(original))
}

// setGatewayClassAccepted inserts or updates the Accepted condition
// for the provided GatewayClass.
func setGatewayClassAccepted(gwc *gatewayv1.GatewayClass, accepted bool) *gatewayv1.GatewayClass {
	gwc.Status.Conditions = merge(gwc.Status.Conditions, gatewayClassAcceptedCondition(gwc, accepted))
	return gwc
}

func (r *gatewayClassReconciler) enqueueRequestForGatewayClassConfig() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(r.enqueueFromIndex(gatewayClassConfigMapIndexName))
}
func (r *gatewayClassReconciler) ensureStatus(ctx context.Context, gwc *gatewayv1.GatewayClass, original *gatewayv1.GatewayClass) error {
	return r.Client.Status().Patch(ctx, gwc, client.MergeFrom(original))
}

func (r *gatewayClassReconciler) enqueueFromIndex(index string) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := r.logger.With(
			logfields.Controller, gatewayClass,
			logfields.Resource, client.ObjectKeyFromObject(o),
		)
		list := &gatewayv1.GatewayClassList{}

		if err := r.Client.List(ctx, list, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(index, client.ObjectKeyFromObject(o).String()),
		}); err != nil {
			scopedLog.Error("Failed to list related GatewayClass", logfields.Error, err)
			return []reconcile.Request{}
		}

		requests := make([]reconcile.Request, 0, len(list.Items))
		for _, item := range list.Items {
			c := client.ObjectKeyFromObject(&item)
			requests = append(requests, reconcile.Request{NamespacedName: c})
			scopedLog.Info("Enqueued GatewayClass for resource", gatewayClass, c)
		}
		return requests
	}
}

func isParameterRefSupported(ref *gatewayv1.ParametersReference) bool {
	if ref == nil {
		return false
	}
	return ref.Group == v2alpha1.CustomResourceDefinitionGroup &&
		ref.Kind == v2alpha1.CGCCKindDefinition
}

// referencedConfig returns a list of CiliumGatewayClassConfig names referenced by the GatewayClass.
func referencedConfig(rawObj client.Object) []string {
	gwc, ok := rawObj.(*gatewayv1.GatewayClass)
	if !ok {
		return nil
	}

	if !isParameterRefSupported(gwc.Spec.ParametersRef) {
		return nil
	}

	if gwc.Spec.ParametersRef.Namespace == nil {
		return nil
	}

	return []string{types.NamespacedName{
		Namespace: string(*gwc.Spec.ParametersRef.Namespace),
		Name:      gwc.Spec.ParametersRef.Name,
	}.String()}
}

// gatewayClassAcceptedCondition returns the GatewayClass with Accepted status condition.
func gatewayClassAcceptedCondition(gwc *gatewayv1.GatewayClass, accepted bool) metav1.Condition {
	switch accepted {
	case true:
		return metav1.Condition{
			Type:               string(gatewayv1.GatewayClassConditionStatusAccepted),
			Status:             metav1.ConditionTrue,
			Reason:             string(gatewayv1.GatewayClassReasonAccepted),
			Message:            gatewayClassAcceptedMessage,
			ObservedGeneration: gwc.Generation,
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	default:
		return metav1.Condition{
			Type:               string(gatewayv1.GatewayClassConditionStatusAccepted),
			Status:             metav1.ConditionFalse,
			Reason:             string(gatewayv1.GatewayClassReasonInvalidParameters),
			Message:            gatewayClassNotAcceptedMessage,
			ObservedGeneration: gwc.Generation,
			LastTransitionTime: metav1.NewTime(time.Now()),
		}
	}
}

// checksum returns a sha256 checksum of CiliumGatewayClassConfig.spec.
// This is used to detect changes in the referenced CiliumGatewayClassConfig.
func checksum(cfg *v2alpha1.CiliumGatewayClassConfig) string {
	hash := sha256.New()
	b, _ := k8syaml.Marshal(cfg.Spec)
	hash.Write(b)
	return fmt.Sprintf("sha256:%x", hash.Sum(nil))
}
func matchesControllerName(controllerName string) func(object client.Object) bool {
	return func(object client.Object) bool {
		gwc, ok := object.(*gatewayv1.GatewayClass)
		if !ok {
			return false
		}
		return string(gwc.Spec.ControllerName) == controllerName
	}
}
