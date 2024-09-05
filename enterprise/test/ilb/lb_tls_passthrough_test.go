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

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestTLSPassthrough(t *testing.T) {
	ctx := context.Background()
	name := "https-passthrough-1"
	ns := "default"
	hostName1 := "passthrough.acme.io"
	hostName2 := "passthrough-2.acme.io"

	ciliumCli, k8sCli := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	// 0. Setup test scenario (backends, clients & LB resources)
	scenario := newLBTestScenario(t, name, ns, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating cert and secret...")
	scenario.createBackendCertificate(ctx, hostName1)
	scenario.createBackendCertificate(ctx, hostName2)

	t.Log("Creating backend apps...")
	scenario.addBackendApplications(ctx, 1, []string{
		"TLS_ENABLED=true",
		"TLS_KEY_BASE64=" + scenario.backendCertificates[hostName1].keyBase64,
		"TLS_CERT_BASE64=" + scenario.backendCertificates[hostName1].certBase64,
	})
	scenario.addBackendApplications(ctx, 1, []string{
		"TLS_ENABLED=true",
		"TLS_KEY_BASE64=" + scenario.backendCertificates[hostName2].keyBase64,
		"TLS_CERT_BASE64=" + scenario.backendCertificates[hostName2].certBase64,
	})

	t.Log("Creating clients and add BGP peering ...")
	scenario.addFrrClients(ctx, 1, []string{}, []string{hostName1, hostName2})

	clientName := name + "-client-0"

	t.Logf("Creating LB VIP resources...")
	vip := lbVIP(ns, name, "")
	scenario.createLBVIP(ctx, vip)

	t.Logf("Creating LB BackendPool resources...")
	backendPool1 := lbBackendPool(ns, name+"-1", "/health", 10, []isovalentv1alpha1.Backend{{IP: scenario.backendApps[name+"-app-0"].ip, Port: 8080}})
	scenario.createLBBackendPool(ctx, backendPool1)

	backendPool2 := lbBackendPool(ns, name+"-2", "/health", 10, []isovalentv1alpha1.Backend{{IP: scenario.backendApps[name+"-app-1"].ip, Port: 8080}})
	scenario.createLBBackendPool(ctx, backendPool2)

	t.Logf("Creating LB Service resources...")
	routes := []isovalentv1alpha1.LBServiceTLSPassthroughRoute{
		{
			Match: &isovalentv1alpha1.LBServiceTLSPassthroughRouteMatch{
				HostNames: []isovalentv1alpha1.LBServiceHostName{
					isovalentv1alpha1.LBServiceHostName(hostName1),
				},
			},
			BackendRef: isovalentv1alpha1.LBServiceBackendRef{
				Name: name + "-1",
			},
		},
		{
			BackendRef: isovalentv1alpha1.LBServiceBackendRef{
				Name: name + "-2",
			},
		},
	}
	service := lbService(ns, name, name, 80, lbServiceApplicationsTLSPassthrough(routes))
	scenario.createLBService(ctx, service)

	// 1. Send HTTPs request

	t.Logf("Waiting for VIP of %q...", name)

	ip, err := ciliumCli.WaitForLBVIP(ctx, ns, name)
	if err != nil {
		t.Fatalf("failed to wait for VIP (%s): %s", name, err)
	}

	err = dockerCli.waitForIPRoute(ctx, clientName, ip)
	if err != nil {
		t.Fatalf("failed to wait for IP route in client (%s): %s", clientName, err)
	}

	testCmd1 := curlCmdVerbose(fmt.Sprintf("--cacert /tmp/%s --resolve %s:80:%s https://%s:80/", hostName1+".crt", hostName1, ip, hostName1))
	testCmd2 := curlCmdVerbose(fmt.Sprintf("--cacert /tmp/%s --resolve %s:80:%s https://%s:80/", hostName2+".crt", hostName2, ip, hostName2))
	for _, testCmd := range []string{testCmd1, testCmd2} {
		t.Logf("Testing %q...", testCmd)
		stdout, stderr, err := dockerCli.clientExec(ctx, clientName, testCmd)
		if err != nil {
			t.Fatalf("curl failed (cmd: %q, stdout: %q, stderr: %q): %s", testCmd, stdout, stderr, err)
		}
	}
}
