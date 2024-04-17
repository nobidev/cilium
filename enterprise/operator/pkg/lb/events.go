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
	"maps"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/addressing"
)

func (lbm *LBManager) handleILBEvent(ctx context.Context, event resource.Event[*isovalent_api_v1alpha1.IsovalentLB]) {
	lbm.logger.Infof("ILB event %s: %s", event.Kind, event.Key)

	obj := event.Object

	var err error
	switch event.Kind {
	case resource.Upsert:
		err = lbm.handleILBUpsert(ctx, obj)
	case resource.Delete:
		err = lbm.handleILBDelete(ctx, obj)
	}

	event.Done(err)
}

func (lbm *LBManager) handleILBUpsert(ctx context.Context, obj *isovalent_api_v1alpha1.IsovalentLB) error {
	lbm.logger.WithFields(logrus.Fields{
		logfields.Resource: obj.Name,
	}).Info("Upsert to IsovalentLB")

	lbls := maps.Clone(obj.Labels)
	if lbls == nil {
		lbls = make(map[string]string, 1)
	}
	lbls["lb.cilium.io/tier"] = "t1"
	annos := maps.Clone(obj.Annotations)
	if annos == nil {
		annos = make(map[string]string, 1)
	}
	annos["io.cilium/lb-ipam-ips"] = obj.Spec.VIP
	// Enable HTTP health-check. Hardcode for now.
	annos["service.cilium.io/health-check-probe-interval"] = obj.Spec.Healthcheck.Interval
	annos["service.cilium.io/health-check-http-path"] = "/health"
	annos["service.cilium.io/health-check-bgp-advertise-threshold"] = "1"
	svc := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        obj.Name,
			Labels:      lbls,
			Annotations: annos,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: v1alpha1.SchemeGroupVersion.String(),
					Kind:       v1alpha1.IsovalentLBKindDefinition,
					Name:       obj.Name,
					UID:        obj.UID,
					// BlockOwnerDeletion: nil,
				},
			},
		},
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeLoadBalancer,
			Ports: []v1.ServicePort{
				{
					Name:     "http",
					Protocol: "TCP",
					Port:     obj.Spec.Port,
				},
			},
		},
	}
	updatedSvc, err := lbm.coreV1Cleint.Services(obj.Namespace).Update(ctx, &svc, metav1.UpdateOptions{})
	if err != nil {
		lbm.logger.WithError(err).WithFields(logrus.Fields{
			logfields.Resource: obj.Name,
		}).Error("Failed to create Service for IsovalentLB")
	}

	eps := v1.Endpoints{
		TypeMeta: metav1.TypeMeta{
			Kind:       "",
			APIVersion: "",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   obj.Name,
			Labels: obj.Labels,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: v1alpha1.SchemeGroupVersion.String(),
					Kind:       v1alpha1.IsovalentLBKindDefinition,
					Name:       obj.Name,
					UID:        obj.UID,
				},
				{
					APIVersion: "v1",
					Kind:       "Service",
					Name:       updatedSvc.Name,
					UID:        updatedSvc.UID,
				},
			},
		},
		Subsets: []v1.EndpointSubset{
			{
				Ports: []v1.EndpointPort{
					{
						Name:     "http",
						Port:     80,
						Protocol: "TCP",
					},
				},
			},
		},
	}
	for _, addr := range lbm.tier2Nodes {
		eps.Subsets[0].Addresses = append(eps.Subsets[0].Addresses, v1.EndpointAddress{IP: addr})
	}
	if _, err := lbm.coreV1Cleint.Endpoints(obj.Namespace).Update(ctx, &eps, metav1.UpdateOptions{}); err != nil {
		lbm.logger.WithError(err).WithFields(logrus.Fields{
			logfields.Resource: obj.Name,
		}).Error("Failed to create Endpoints for IsovalentLB")
	}

	cec, err := lbm.populateCEC(obj, updatedSvc)
	if err != nil {
		return err
	}
	if oldCEC, exists, _ := lbm.envoyConfigStore.GetByKey(resource.NewKey(cec)); exists {
		cec.ResourceVersion = oldCEC.ResourceVersion
		if _, err := lbm.cecClient.CiliumEnvoyConfigs(obj.Namespace).Update(ctx, cec, metav1.UpdateOptions{}); err != nil {
			lbm.logger.WithError(err).WithFields(logrus.Fields{
				logfields.Resource: obj.Name,
			}).Error("Failed to update CEC for IsovalentLB")
		}
	} else {
		if _, err := lbm.cecClient.CiliumEnvoyConfigs(obj.Namespace).Create(ctx, cec, metav1.CreateOptions{}); err != nil {
			lbm.logger.WithError(err).WithFields(logrus.Fields{
				logfields.Resource: obj.Name,
			}).Error("Failed to create CEC for IsovalentLB")
		}
	}

	return nil
}

func (lbm *LBManager) handleILBDelete(ctx context.Context, obj *isovalent_api_v1alpha1.IsovalentLB) error {
	lbm.logger.WithFields(logrus.Fields{
		logfields.Resource: obj.Name,
	}).Info("Delete to IsovalentLB")

	if err := lbm.coreV1Cleint.Services(obj.Namespace).Delete(ctx, obj.Name, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
		lbm.logger.WithError(err).WithFields(logrus.Fields{
			logfields.Resource: obj.Name,
		}).Error("Failed to delete Service for IsovalentLB")
	}
	if err := lbm.coreV1Cleint.Endpoints(obj.Namespace).Delete(ctx, obj.Name, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
		lbm.logger.WithError(err).WithFields(logrus.Fields{
			logfields.Resource: obj.Name,
		}).Error("Failed to delete Endpoints for IsovalentLB")
	}
	if err := lbm.cecClient.CiliumEnvoyConfigs(obj.Namespace).Delete(ctx, obj.Name, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
		lbm.logger.WithError(err).WithFields(logrus.Fields{
			logfields.Resource: obj.Name,
		}).Error("Failed to delete CEC for IsovalentLB")
	}

	return nil
}

func (lbm *LBManager) handleNodeEvent(_ context.Context, event resource.Event[*cilium_api_v2.CiliumNode]) {
	defer event.Done(nil)

	switch event.Kind {
	case resource.Upsert:
		if v := event.Object.Labels["lb.cilium.io/tier"]; v == "t2" {
			var ip string
			for _, addr := range event.Object.Spec.Addresses {
				if addr.Type == addressing.NodeInternalIP {
					ip = addr.IP
					break
				}
			}
			if ip == "" {
				lbm.logger.WithFields(logrus.Fields{
					logfields.Resource: event.Object.Name,
				}).Warn("Could not find InternalIP for a tier 2 CiliumNode")
				break
			}
			lbm.tier2Nodes[event.Object.Name] = ip

			// TODO: Trigger reconciliation to update the Endpoints' addresses.
		}
	case resource.Delete:
		delete(lbm.tier2Nodes, event.Object.Name)
		// TODO: Trigger reconciliation to update the Endpoints' addresses.
	}
}
