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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ciliumiov2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/versioncheck"
)

func TestLabelBasedBackend_CNP_T1T2(t T) {
	testLabelBasedBackendCNP(t, isovalentv1alpha1.LBTCPProxyForceDeploymentModeType(isovalentv1alpha1.LBTCPProxyDeploymentModeTypeT1T2))
}

func testLabelBasedBackendCNP(t T, mode isovalentv1alpha1.LBTCPProxyForceDeploymentModeType) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// label based backends are only supported in v1.18 and newer
	minVersion := ">=1.18.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
		return
	}

	testName := "labelbased-backend-cnp-" + string(mode)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend apps...")
	_ = scenario.AddAndWaitForK8sBackendApplications(testName, 2, "", map[string]string{"service.cilium.io/node": "t2"})

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{})[0]

	t.Log("Creating LB VIP resources...")
	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")
	backends := []backendPoolOption{}
	backends = append(backends, withK8sServiceBackend(testName, 8080))
	backendPool := lbBackendPool(testName, backends...)
	scenario.createLBBackendPool(backendPool)

	t.Log("Creating LB Service resources...")
	service := lbService(testName, withPort(80), withHTTPProxyApplication(withHttpRoute(backendPool.Name)))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// 1. Send HTTP request to test basic client -> LB T1 -> LB T2 -> app connectivity
	t.Log("Checking connectivity without CNP applied ...")
	{
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' http://%s:80/", vipIP))
		t.Log("Testing %q...", testCmd)
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	}

	{
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' http://%s:80/special", vipIP))
		t.Log("Testing %q...", testCmd)
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	}

	t.Log("Applying Ingress CNP...")
	cnp := podIngressL7CNP(scenario.k8sNamespace)

	_, err := ciliumCli.CiliumV2().CiliumNetworkPolicies(scenario.k8sNamespace).Create(t.Context(), cnp, metav1.CreateOptions{})
	if err != nil {
		t.Failedf("failed to create CNP")
	}
	t.RegisterCleanup(func(ctx context.Context) error {
		return ciliumCli.CiliumV2().CiliumNetworkPolicies(scenario.k8sNamespace).Delete(ctx, cnp.Name, metav1.DeleteOptions{})
	})

	t.Log("Checking that CNP matches Ingress identity and blocks path != / ...")
	{
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' http://%s:80/", vipIP))
		t.Log("Testing %q...", testCmd)
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	}

	eventually(t, func() error {
		testCmd := curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' http://%s:80/special", vipIP))
		t.Log("Testing %q...", testCmd)
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err == nil {
			return fmt.Errorf("curl succeeded (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
		}
		return nil
	}, shortTimeout, pollInterval)
}

func podIngressL7CNP(namespace string) *ciliumiov2.CiliumNetworkPolicy {
	return &ciliumiov2.CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "labelbased-backend-cnp-t1-t2",
		},
		Spec: &policyapi.Rule{
			EndpointSelector: policyapi.EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]slim_metav1.MatchLabelsValue{
						"app": "labelbased-backend-cnp-t1-t2",
					},
				},
			},
			Ingress: []policyapi.IngressRule{
				{
					IngressCommonRule: policyapi.IngressCommonRule{
						FromEntities: policyapi.EntitySlice{
							policyapi.EntityIngress,
						},
					},
					ToPorts: policyapi.PortRules{
						{
							Ports: []policyapi.PortProtocol{
								{
									Protocol: policyapi.ProtoTCP,
									Port:     "8080",
								},
							},
							Rules: &policyapi.L7Rules{
								HTTP: []policyapi.PortRuleHTTP{
									{
										Path: "/",
									},
								},
							},
						},
					},
				},
			},
		},
	}
}
