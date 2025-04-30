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
	"fmt"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestLabelBasedBackend_T1T2(t T) {
	testLabelBasedBackend(t, isovalentv1alpha1.LBTCPProxyForceDeploymentModeType(isovalentv1alpha1.LBTCPProxyDeploymentModeTypeT1T2))
}

func TestLabelBasedBackend_T1Only(t T) {
	testLabelBasedBackend(t, isovalentv1alpha1.LBTCPProxyForceDeploymentModeType(isovalentv1alpha1.LBTCPProxyDeploymentModeTypeT1Only))
}

func testLabelBasedBackend(t T, mode isovalentv1alpha1.LBTCPProxyForceDeploymentModeType) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	testK8sNamespace := "default"

	testName := "labelbased-backend-" + string(mode)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")
	desiredBackends := scenario.AddAndWaitForK8sBackendApplications(testK8sNamespace, testName, 2, "")

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{})[0]

	t.Log("Creating LB VIP resources...")
	vip := lbVIP(testK8sNamespace, testName)
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	backends = append(backends, withK8sServiceBackend(testName, 8080))
	backendPool := lbBackendPool(testK8sNamespace, testName, backends...)
	scenario.createLBBackendPool(backendPool)

	t.Log("Creating LB Service resources...")
	service := lbService(testK8sNamespace, testName, withPort(80), withTCPProxyApplication(withTCPForceDeploymentMode(mode), withTCPProxyRoute(backendPool.Name)))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// 1. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity
	testCmd := curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' http://%s:80/", vipIP))
	t.Log("Testing %q...", testCmd)
	stdout, stderr, err := client.Exec(t.Context(), testCmd)
	if err != nil {
		t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
	}

	observedBackends := make(map[string]struct{})
	eventually(t, func() error {
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
		}

		// Response from the health check server contains instance name (Pod name in this case)
		appResponse := toTestAppResponse(t, stdout)

		for _, pod := range desiredBackends.Items {
			if appResponse.InstanceName == pod.Name {
				observedBackends[pod.Name] = struct{}{}
			}
		}

		// Check if we have observed all backends
		if len(observedBackends) != len(desiredBackends.Items) {
			return fmt.Errorf("have not observed all backends yet: %d/%d", len(observedBackends), len(desiredBackends.Items))
		}

		return nil
	}, longTimeout, pollInterval)
}
