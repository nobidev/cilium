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
)

func TestTLSPassthrough(t T) {
	testName := "https-passthrough-1"
	hostName1 := "passthrough.acme.io"
	hostName2 := "passthrough-2.acme.io"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating cert and secret...")
	scenario.createBackendServerCertificate(hostName1)
	scenario.createBackendServerCertificate(hostName2)

	t.Log("Creating backend apps...")
	backend1 := scenario.addBackendApplications(1, backendApplicationConfig{tlsCertHostname: hostName1, listenPort: 8080})[0]
	backend2 := scenario.addBackendApplications(1, backendApplicationConfig{tlsCertHostname: hostName2, listenPort: 8081})[0]

	t.Log("Creating clients and add BGP peering ...")
	client := scenario.addFRRClients(1, frrClientConfig{trustedCertsHostnames: []string{hostName1, hostName2}})[0]

	t.Log("Creating LB VIP resources...")
	vip := lbVIP(testName)
	scenario.createLBVIP(vip)

	t.Log("Creating LB BackendPool resources...")
	backendPool1 := lbBackendPool(testName+"-1", withIPBackend(backend1.ipv4, 8080), withHealthCheckTLS())
	scenario.createLBBackendPool(backendPool1)

	backendPool2 := lbBackendPool(testName+"-2", withIPBackend(backend2.ipv4, 8081), withHealthCheckTLS())
	scenario.createLBBackendPool(backendPool2)

	t.Log("Creating LB Service resources...")
	service := lbService(testName, withTLSPassthroughApplication(
		withTLSPassthroughRoute(testName+"-1", withTLSPassthroughHostname(hostName1)),
		withTLSPassthroughRoute(testName+"-2"),
	))
	scenario.createLBService(service)

	t.Log("Waiting for full VIP connectivity...")
	vipIP := scenario.waitForFullVIPConnectivity(testName)

	// 1. Send HTTPs request
	testCmd1 := curlCmdVerbose(fmt.Sprintf("--max-time 10 --cacert /tmp/%s --resolve %s:80:%s https://%s:80/", hostName1+".crt", hostName1, vipIP, hostName1))
	testCmd2 := curlCmdVerbose(fmt.Sprintf("--max-time 10 --cacert /tmp/%s --resolve %s:80:%s https://%s:80/", hostName2+".crt", hostName2, vipIP, hostName2))
	for _, testCmd := range []string{testCmd1, testCmd2} {
		t.Log("Testing %q...", testCmd)
		stdout, stderr, err := client.Exec(t.Context(), testCmd)
		if err != nil {
			t.Failedf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	}
}
