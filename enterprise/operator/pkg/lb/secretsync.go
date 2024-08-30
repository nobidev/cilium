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
	"log/slog"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func enqueueTLSSecrets(_ client.Client, logger logrus.FieldLogger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		scopedLog := logger.WithFields(logrus.Fields{
			logfields.Controller: "secrets",
			logfields.Resource:   obj.GetName(),
		})

		lbFrontend, ok := obj.(*isovalentv1alpha1.LBService)
		if !ok {
			return nil
		}

		var reqs []reconcile.Request
		if lbFrontend.Spec.Applications.HTTPSProxy == nil || lbFrontend.Spec.Applications.HTTPSProxy.TLSConfig == nil {
			return reqs
		}

		// TLS certificates secrets
		for _, c := range lbFrontend.Spec.Applications.HTTPSProxy.TLSConfig.Certificates {
			s := types.NamespacedName{
				Namespace: lbFrontend.Namespace,
				Name:      c.SecretRef.Name,
			}
			reqs = append(reqs, reconcile.Request{NamespacedName: s})
			scopedLog.WithField("secret", s).Debug("Enqueued secret for LBService")
		}

		// TLS validation secret
		if lbFrontend.Spec.Applications.HTTPSProxy.TLSConfig.Validation != nil {
			s := types.NamespacedName{
				Namespace: lbFrontend.Namespace,
				Name:      lbFrontend.Spec.Applications.HTTPSProxy.TLSConfig.Validation.SecretRef.Name,
			}
			reqs = append(reqs, reconcile.Request{NamespacedName: s})
			scopedLog.WithField("secret", s).Debug("Enqueued secret for LBService")
		}

		return reqs
	})
}

func isReferencedByLBFrontend(ctx context.Context, c client.Client, logger *slog.Logger, secret *corev1.Secret) bool {
	return len(getLBFrontendsForSecret(ctx, c, logger, secret)) > 0
}

func getLBFrontendsForSecret(ctx context.Context, c client.Client, logger *slog.Logger, secret *corev1.Secret) []*isovalentv1alpha1.LBService {
	lbList := isovalentv1alpha1.LBServiceList{}

	listOps := &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(lbFrontendTlsSecretsIndexName, secret.GetName()),
		Namespace:     secret.GetNamespace(),
	}

	if err := c.List(ctx, &lbList, listOps); err != nil {
		logger.Warn("Failed to list LBServices", logfields.Error, err)
		return nil
	}

	result := []*isovalentv1alpha1.LBService{}

	for _, i := range lbList.Items {
		lbfe := i
		result = append(result, &lbfe)
	}

	return result
}
