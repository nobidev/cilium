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

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestTCPProxyPersistentBackend(t *testing.T) {
	skipIfOnSingleNode(t, ">1 FRR clients are not supported")

	ctx := context.Background()
	ns := "default"
	testName := "tcp-proxy-persistent-backend"

	ciliumCli, k8sCli := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	scenario := newLBTestScenario(t, testName, ns, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend app...")

	scenario.addBackendApplications(ctx, 2, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating client and add BGP peering...")

	clients := scenario.addFRRClients(ctx, 2, frrClientConfig{})

	t.Logf("Creating LB VIP resources...")

	vip := lbVIP(ns, testName)
	scenario.createLBVIP(ctx, vip)

	t.Log("Creating LB BackendPool resources...")

	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withIPBackend(b.ip, b.port))
	}
	backendPool := lbBackendPool(ns, testName, backends...)
	backendPool.Spec.Loadbalancing = &isovalentv1alpha1.Loadbalancing{
		Algorithm: isovalentv1alpha1.LoadbalancingAlgorithm{
			ConsistentHashing: &isovalentv1alpha1.LoadbalancingAlgorithmConsistentHashing{},
		},
	}
	scenario.createLBBackendPool(ctx, backendPool)

	t.Log("Creating LB Service resources...")

	service := lbService(ns, testName, withPort(80), withTCPProxyApplication(withTCPProxyRoute(backendPool.Name, withTCPProxyBackendPersistenceBySourceIP())))
	scenario.createLBService(ctx, service)

	t.Logf("Waiting for full VIP connectivity of %q...", testName)
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	maybeSysdump(t, testName, "")

	// 1. Test persistent backend selection with source IP
	{
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' http://%s:80/", vipIP))
		t.Logf("Testing backend selection persistence of 100 requests: %q...", testCmd)
		testPersistenceWith100Requests(t, ctx, clients[0], testCmd)
	}

	{
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' http://%s:80/", vipIP))
		t.Logf("Testing backend selection persistence of 100 requests: %q...", testCmd)
		testPersistenceWith100Requests(t, ctx, clients[1], testCmd)
	}
}

func TestTCPProxyPersistentBackend_Fail_T1Only(t *testing.T) {
	ctx := context.Background()
	ns := "default"
	testName := "tcp-proxy-persistent-backend-fail-t1-only"

	ciliumCli, _ := newCiliumAndK8sCli(t)

	service := lbService(ns, testName, withPort(10080), withTCPProxyApplication(withTCPForceDeploymentMode(isovalentv1alpha1.LBTCPProxyForceDeploymentModeT1), withTCPProxyRoute("fake", withTCPProxyBackendPersistenceBySourceIP())))

	err := ciliumCli.CreateLBService(ctx, ns, service, metav1.CreateOptions{})
	assert.Error(t, err)
	assert.ErrorContains(t, err, "Force deployment mode t1-only isn't compatible with persistent backends and rate limits")
}
