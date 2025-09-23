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
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrlClient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlFakeClient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ceeannotation "github.com/cilium/cilium/enterprise/pkg/annotation"
	ossannotation "github.com/cilium/cilium/pkg/annotation"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestLBVIPReconciler(t *testing.T) {
	const (
		namespace = "default"
		lbvipName = "test"
		ipv4VIP   = "10.0.0.1"
	)
	tests := []struct {
		// Case name
		name string

		// Input LBVIP spec
		lbvipSpec isovalentv1alpha1.LBVIPSpec

		// Output Service annotations. Rest of the fields are fixed.
		svcAnnotations map[string]string

		// Output Service labels. Rest of the fields are fixed.
		svcLabels map[string]string
	}{
		{
			name:      "IPv4 dynamic allocation",
			lbvipSpec: isovalentv1alpha1.LBVIPSpec{},
			svcLabels: map[string]string{
				"loadbalancer.isovalent.com/vip-name": lbvipName,
			},
			svcAnnotations: map[string]string{
				ossannotation.LBIPAMSharingKey:       lbvipName,
				ceeannotation.ServiceNoAdvertisement: "true",
			},
		},
		{
			name: "IPv4 static allocation",
			lbvipSpec: isovalentv1alpha1.LBVIPSpec{
				IPv4Request: ptr.To(ipv4VIP),
			},
			svcLabels: map[string]string{
				"loadbalancer.isovalent.com/vip-name": lbvipName,
			},
			svcAnnotations: map[string]string{
				ossannotation.LBIPAMSharingKey:       lbvipName,
				ossannotation.LBIPAMIPsKey:           ipv4VIP,
				ceeannotation.ServiceNoAdvertisement: "true",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize fake client
			scheme := clientgoscheme.Scheme
			isovalentv1alpha1.AddToScheme(scheme)
			c := ctrlFakeClient.
				NewClientBuilder().
				WithStatusSubresource(&isovalentv1alpha1.LBVIP{}).
				Build()

			logger := slog.New(slog.DiscardHandler)

			r := newLBVIPReconciler(lbVIPReconcilerParams{
				logger: logger,
				client: c,
				scheme: scheme,
			})

			lbvip := &isovalentv1alpha1.LBVIP{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      lbvipName,
				},
				Spec: tt.lbvipSpec,
			}

			// Create an LBVIP
			require.NoError(t, c.Create(context.TODO(), lbvip))

			// Initial reconciliation to create the Service
			_, err := r.Reconcile(
				context.TODO(),
				reconcile.Request{
					NamespacedName: k8stypes.NamespacedName{
						Namespace: lbvip.Namespace,
						Name:      lbvip.Name,
					},
				},
			)
			require.NoError(t, err)

			// Ensure the expected Service has been created
			svc := &corev1.Service{}

			// Ensure the Service is created with the expected namespace and name
			require.NoError(t, c.Get(
				context.TODO(),
				ctrlClient.ObjectKey{
					Namespace: lbvip.Namespace,
					Name:      placeholderServicePrefix + lbvip.Name,
				},
				svc,
			))

			// Ensure the annotations and labels match the expected ones
			require.Equal(t, tt.svcAnnotations, svc.Annotations)
			require.Equal(t, tt.svcLabels, svc.Labels)

			// Assign VIP to the Service. Emulate the behavior of the LBIPAM.
			svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
				{
					IP: ipv4VIP,
				},
			}
			require.NoError(t, c.Status().Update(context.TODO(), svc))

			// The second reconciliation to update the LBVIP status
			_, err = r.Reconcile(
				context.TODO(),
				reconcile.Request{
					NamespacedName: k8stypes.NamespacedName{
						Namespace: lbvip.Namespace,
						Name:      lbvip.Name,
					},
				},
			)
			require.NoError(t, err)

			// Ensure the LBVIP status is updated
			require.NoError(t, c.Get(
				context.TODO(),
				ctrlClient.ObjectKeyFromObject(lbvip),
				lbvip,
			))

			// Ensure the LBVIP status is updated with the expected VIP
			require.Equal(t, ipv4VIP, *lbvip.Status.Addresses.IPv4)
		})
	}
}
