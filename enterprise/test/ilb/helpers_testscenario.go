//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import (
	"context"
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

type lbTestScenario struct {
	t *testing.T

	testName     string
	k8sNamespace string

	ciliumCli *ciliumCli
	dockerCli *dockerCli

	backendApps map[string]*backendApp
	frrClients  map[string]*backendApp
}

type backendApp struct {
	id string
	ip string
}

func newLBTestScenario(t *testing.T, testName string, k8sNamespace string, ciliumCli *ciliumCli, dockerCli *dockerCli) *lbTestScenario {
	return &lbTestScenario{
		t:            t,
		testName:     testName,
		k8sNamespace: k8sNamespace,
		ciliumCli:    ciliumCli,
		dockerCli:    dockerCli,
		backendApps:  map[string]*backendApp{},
		frrClients:   map[string]*backendApp{},
	}
}

func (r *lbTestScenario) addBackendApplications(ctx context.Context, numberOfBackends int, additionalEnvVars []string) {
	startIndex := len(r.backendApps)

	for i := startIndex; i < startIndex+numberOfBackends; i++ {
		appName := fmt.Sprintf("%s-app-%d", r.testName, i)

		env := []string{
			"SERVICE_NAME=" + appName,
			"INSTANCE_NAME=" + appName,
		}

		env = append(env, additionalEnvVars...)

		id, ip, err := r.dockerCli.createContainer(ctx, appName, appImage, env, containerNetwork, false)
		if err != nil {
			r.t.Fatalf("cannot create app container (%s): %s", appName, err)
		}

		r.backendApps[appName] = &backendApp{
			id: id,
			ip: ip,
		}

		maybeCleanupT(func() error { return r.dockerCli.deleteContainer(context.Background(), id) }, r.t)
	}
}

func (r *lbTestScenario) addFrrClients(ctx context.Context, numberOfClients int, additionalEnvVars []string) {
	startIndex := len(r.frrClients)

	for i := startIndex; i < startIndex+numberOfClients; i++ {
		clientName := fmt.Sprintf("%s-client-%d", r.testName, i)

		env := []string{
			"NEIGHBORS=" + getBGPNeighborString(r.t, r.dockerCli),
		}

		env = append(env, additionalEnvVars...)

		id, ip, err := r.dockerCli.createContainer(ctx, clientName, clientImage, env, containerNetwork, true)
		if err != nil {
			r.t.Fatalf("cannot create frr client container (%s): %s", clientName, err)
		}

		r.frrClients[clientName] = &backendApp{
			id: id,
			ip: ip,
		}

		maybeCleanupT(func() error { return r.dockerCli.deleteContainer(context.Background(), id) }, r.t)

		if err := r.ciliumCli.doBGPPeeringForClient(ctx, ip); err != nil {
			r.t.Fatalf("failed to BGP peer (%s): %s", clientName, err)
		}
		maybeCleanupT(func() error { return r.ciliumCli.undoBGPPeeringForClient(context.Background(), ip) }, r.t)
	}
}

func (r *lbTestScenario) createLBVIP(ctx context.Context, vip *isovalentv1alpha1.LBVIP) {
	if err := r.ciliumCli.CreateLBVIP(ctx, r.k8sNamespace, vip, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			r.t.Fatalf("cannot create LB VIP (%s): %s", r.testName, err)
		}
	}
	maybeCleanupT(func() error {
		return r.ciliumCli.DeleteLBVIP(ctx, vip.Namespace, vip.Name, metav1.DeleteOptions{})
	}, r.t)
}

func (r *lbTestScenario) createLBBackendPool(ctx context.Context, bp *isovalentv1alpha1.LBBackendPool) {
	if err := r.ciliumCli.CreateLBBackendPool(ctx, r.k8sNamespace, bp, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			r.t.Fatalf("cannot create LB BackendPool (%s): %s", r.testName, err)
		}
	}
	maybeCleanupT(func() error {
		return r.ciliumCli.DeleteLBBackendPool(ctx, bp.Namespace, bp.Name, metav1.DeleteOptions{})
	}, r.t)
}

func (r *lbTestScenario) createLBService(ctx context.Context, svc *isovalentv1alpha1.LBService) {
	if err := r.ciliumCli.CreateLBService(ctx, r.k8sNamespace, svc, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			r.t.Fatalf("cannot create LB Service (%s): %s", r.testName, err)
		}
	}
	maybeCleanupT(func() error {
		return r.ciliumCli.DeleteLBService(ctx, svc.Namespace, svc.Name, metav1.DeleteOptions{})
	}, r.t)
}
