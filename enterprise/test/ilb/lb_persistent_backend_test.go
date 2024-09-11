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
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/safeio"
	"github.com/cilium/cilium/pkg/time"
)

func TestPersistentBackendWithCookie(t *testing.T) {
	ctx := context.Background()
	testName := "pers-backend-cookie-1"
	testK8sNamespace := "default"

	ciliumCli, k8sCli := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(ctx, 2, backendApplicationConfig{})

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(ctx, 1, frrClientConfig{})[0]

	t.Logf("Creating LB VIP resources...")
	vip := lbVIP(testK8sNamespace, testName)
	scenario.createLBVIP(ctx, vip)

	t.Logf("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withBackend(b.ip, 8080))
	}
	backendPool := lbBackendPool(testK8sNamespace, testName, backends...)
	backendPool.Spec.Loadbalancing = &isovalentv1alpha1.Loadbalancing{
		Algorithm: isovalentv1alpha1.LoadbalancingAlgorithm{
			ConsistentHashing: &isovalentv1alpha1.LoadbalancingAlgorithmConsistentHashing{},
		},
	}
	scenario.createLBBackendPool(ctx, backendPool)

	t.Logf("Creating LB Service resources...")
	service := lbService(testK8sNamespace, testName, withHTTPProxyApplication(testName, withHttpBackendPersistenceByCookie("session")))
	scenario.createLBService(ctx, service)

	t.Logf("Waiting for full VIP connectivity of %q...", testName)
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	// 1. Test persistent backend selection with cookie
	{
		testCmd := curlCmdVerbose(fmt.Sprintf("-m 2 --cookie 'session=123' http://%s:80/test1", vipIP))
		t.Logf("Testing 100 requests: %q...", testCmd)
		for i := 0; i < 100; i++ {
			stdout, stderr, err := client.Exec(ctx, testCmd)
			if err != nil {
				t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
			}
		}
	}

	t.Log("Check backend persistence")
	eventually(t, checkForPersistentBackend(ctx, dockerCli, scenario, "test1"), 10*time.Second, 1*time.Second)

	{
		testCmd := curlCmdVerbose(fmt.Sprintf("-m 2 --cookie 'session=234' http://%s:80/test2", vipIP))
		t.Logf("Testing 100 requests: %q...", testCmd)
		for i := 0; i < 100; i++ {
			stdout, stderr, err := client.Exec(ctx, testCmd)
			if err != nil {
				t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
			}
		}
	}

	t.Log("Check backend persistence")
	eventually(t, checkForPersistentBackend(ctx, dockerCli, scenario, "test2"), 10*time.Second, 1*time.Second)
}

func TestPersistentBackendWithSourceIP(t *testing.T) {
	ctx := context.Background()
	testName := "pers-backend-sourceip-1"
	testK8sNamespace := "default"

	ciliumCli, k8sCli := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(ctx, 2, backendApplicationConfig{})

	t.Log("Creating clients and add BGP peering ...")
	clients := scenario.addFRRClients(ctx, 2, frrClientConfig{})

	t.Logf("Creating LB VIP resources...")
	vip := lbVIP(testK8sNamespace, testName)
	scenario.createLBVIP(ctx, vip)

	t.Logf("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	for _, b := range scenario.backendApps {
		backends = append(backends, withBackend(b.ip, 8080))
	}
	backendPool := lbBackendPool(testK8sNamespace, testName, backends...)
	backendPool.Spec.Loadbalancing = &isovalentv1alpha1.Loadbalancing{
		Algorithm: isovalentv1alpha1.LoadbalancingAlgorithm{
			ConsistentHashing: &isovalentv1alpha1.LoadbalancingAlgorithmConsistentHashing{},
		},
	}
	scenario.createLBBackendPool(ctx, backendPool)

	t.Logf("Creating LB Service resources...")
	service := lbService(testK8sNamespace, testName, withHTTPProxyApplication(testName, withHttpBackendPersistenceBySourceIP()))
	scenario.createLBService(ctx, service)

	t.Logf("Waiting for full VIP connectivity of %q...", testName)
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	// 1. Test persistent backend selection with source IP
	{
		testCmd := curlCmdVerbose(fmt.Sprintf("-m 2 http://%s:80/test1", vipIP))
		t.Logf("Testing 100 requests: %q...", testCmd)
		for i := 0; i < 100; i++ {
			stdout, stderr, err := clients[0].Exec(ctx, testCmd)
			if err != nil {
				t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
			}
		}
	}

	t.Log("Check backend persistence")
	eventually(t, checkForPersistentBackend(ctx, dockerCli, scenario, "test1"), 10*time.Second, 1*time.Second)

	{
		testCmd := curlCmdVerbose(fmt.Sprintf("-m 2 http://%s:80/test2", vipIP))
		t.Logf("Testing 100 requests: %q...", testCmd)
		for i := 0; i < 100; i++ {
			stdout, stderr, err := clients[1].Exec(ctx, testCmd)
			if err != nil {
				t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
			}
		}
	}

	t.Log("Check backend persistence")
	eventually(t, checkForPersistentBackend(ctx, dockerCli, scenario, "test2"), 10*time.Second, 1*time.Second)
}

func checkForPersistentBackend(ctx context.Context, dockerCli *dockerCli, scenario *lbTestScenario, path string) func() error {
	return func() error {
		allRequestsServedByOneBackend := false
		totalHandledRequests := 0

		for _, b := range scenario.backendApps {
			rc, err := dockerCli.ContainerLogs(ctx, b.id, container.LogsOptions{ShowStdout: true, ShowStderr: true})
			if err != nil {
				return fmt.Errorf("failed to get backend container logs: %w", err)
			}
			defer rc.Close()

			log, err := safeio.ReadAllLimit(rc, safeio.GB)
			if err != nil {
				return fmt.Errorf("failed to read backend container logs: %w", err)
			}

			handledRequests := strings.Count(string(log), fmt.Sprintf("Service request request.path=/%s", path))

			if handledRequests == 100 {
				allRequestsServedByOneBackend = true
			}

			totalHandledRequests += handledRequests
		}

		if totalHandledRequests != 100 {
			return fmt.Errorf("unexpected total number of handled requests: %d", totalHandledRequests)
		}

		if !allRequestsServedByOneBackend {
			return errors.New("no backend served all requests")
		}

		return nil
	}
}
