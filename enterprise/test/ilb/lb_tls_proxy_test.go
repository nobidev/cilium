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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestTLSProxyTCPBackend(t *testing.T) {
	ctx := context.Background()
	ns := "default"
	testName := "tls-proxy-tcp-backend"
	serviceHostName := "secure.acme.io"
	clientHostName := "client.acme.io"

	ciliumCli, k8sCli := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	scenario := newLBTestScenario(t, testName, ns, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating cert and secret...")

	scenario.createLBServerCertificate(ctx, serviceHostName)
	scenario.createLBClientCertificate(ctx, clientHostName)

	t.Logf("Creating LB VIP resources...")

	vip := lbVIP(ns, testName)
	scenario.createLBVIP(ctx, vip)

	t.Log("Creating backend app...")

	backends := scenario.addBackendApplications(ctx, 1, backendApplicationConfig{h2cEnabled: true})

	t.Log("Creating client and add BGP peering...")

	scenario.addFRRClients(ctx, 1, frrClientConfig{trustedCertsHostnames: []string{serviceHostName}})

	// FIXME: Don't expose internal naming convention. Get it from the scenario instead.
	clientName := testName + "-client-0"
	clientCertSecretName := testName + "-client"

	t.Log("Creating LB BackendPool resources...")

	backendPool := lbBackendPool(ns, testName, withBackend(backends[0].ip, 8080))
	scenario.createLBBackendPool(ctx, backendPool)

	t.Log("Creating LB Service resources...")

	service := lbService(ns, testName, withPort(10080), withTLSProxyApplication(backendPool.Name, testName, serviceHostName))
	scenario.createLBService(ctx, service)

	t.Logf("Waiting for full VIP connectivity of %q...", testName)
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	// 3. Test basic connectivity
	t.Run("Basic Connectivity", func(t *testing.T) {
		testCmd := curlCmdVerbose(fmt.Sprintf("-m 1 --cacert /tmp/%s.crt --resolve secure.acme.io:10080:%s https://secure.acme.io:10080/", serviceHostName, vipIP))

		t.Logf("Testing %q...", testCmd)

		eventually(t, func() error {
			stdout, stderr, err := dockerCli.clientExec(ctx, clientName, testCmd)
			if err != nil {
				// Enrich error with curl output
				err = fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
			}
			return err
		}, 10*time.Second, 100*time.Millisecond)
	})

	// 4. Test mTLS connectivity
	t.Run("mTLS Connectivity", func(t *testing.T) {
		curSvc, err := ciliumCli.GetLBService(ctx, ns, testName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("failed to get LB service (%s): %s", testName, err)
		}

		// Add validation context to the TLS config and update
		curSvc.Spec.Applications.TLSProxy.TLSConfig.Validation = &isovalentv1alpha1.LBTLSValidationConfig{
			SecretRef: isovalentv1alpha1.LBServiceSecretRef{
				Name: clientCertSecretName,
			},
		}

		if err := ciliumCli.UpdateLBService(ctx, ns, curSvc, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("failed to update LB service (%s): %s", testName, err)
		}

		testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 1 --cert /tmp/%s.crt --key /tmp/%s.key --cacert /tmp/%s.crt --resolve secure.acme.io:10080:%s https://secure.acme.io:10080/",
			clientHostName, clientHostName, serviceHostName, vipIP))

		t.Logf("Testing %q...", testCmd)

		eventually(t, func() error {
			stdout, stderr, err := dockerCli.clientExec(ctx, clientName, testCmd)
			if err != nil {
				// Enrich error with curl output
				err = fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
			}
			return err
		}, 10*time.Second, 100*time.Millisecond)
	})
}

func TestTLSProxyTLSBackend(t *testing.T) {
	ctx := context.Background()
	ns := "default"
	testName := "tls-proxy-tls-backend"
	serviceHostName := "secure.acme.io"
	clientHostName := "client.acme.io"

	ciliumCli, k8sCli := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	scenario := newLBTestScenario(t, testName, ns, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating cert and secret...")

	scenario.createLBServerCertificate(ctx, serviceHostName)
	scenario.createLBClientCertificate(ctx, clientHostName)

	t.Logf("Creating LB VIP resources...")

	vip := lbVIP(ns, testName)
	scenario.createLBVIP(ctx, vip)

	backendHostName := "secure-backend.acme.io"

	t.Log("Creating backend certificate...")

	scenario.createBackendServerCertificate(ctx, backendHostName)

	t.Log("Creating backend app...")

	backends := scenario.addBackendApplications(ctx, 1, backendApplicationConfig{tlsCertHostname: backendHostName})

	t.Log("Creating client and add BGP peering...")

	scenario.addFRRClients(ctx, 1, frrClientConfig{trustedCertsHostnames: []string{serviceHostName}})

	// FIXME: Don't expose internal naming convention. Get it from the scenario instead.
	clientName := testName + "-client-0"
	clientCertSecretName := testName + "-client"

	t.Log("Creating LB BackendPool resources...")

	backendPool := lbBackendPool(ns, testName, withBackend(backends[0].ip, 8080), withBackendTLS())
	scenario.createLBBackendPool(ctx, backendPool)

	t.Log("Creating LB Service resources...")

	service := lbService(ns, testName, withPort(10443), withTLSProxyApplication(backendPool.Name, testName, serviceHostName))
	scenario.createLBService(ctx, service)

	t.Logf("Waiting for full VIP connectivity of %q...", testName)
	vipIP := scenario.waitForFullVIPConnectivity(ctx, testName)

	// 3. Test basic connectivity
	t.Run("Basic Connectivity", func(t *testing.T) {
		testCmd := curlCmdVerbose(fmt.Sprintf("-m 1 --cacert /tmp/%s.crt --resolve secure.acme.io:10443:%s https://secure.acme.io:10443/", serviceHostName, vipIP))

		t.Logf("Testing %q...", testCmd)

		eventually(t, func() error {
			stdout, stderr, err := dockerCli.clientExec(ctx, clientName, testCmd)
			if err != nil {
				// Enrich error with curl output
				return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
			}
			return nil
		}, 10*time.Second, 100*time.Millisecond)
	})

	// 4. Test mTLS connectivity
	t.Run("mTLS Connectivity", func(t *testing.T) {
		curSvc, err := ciliumCli.GetLBService(ctx, ns, testName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("failed to get LB service (%s): %s", testName, err)
		}

		// Add validation context to the TLS config and update
		curSvc.Spec.Applications.TLSProxy.TLSConfig.Validation = &isovalentv1alpha1.LBTLSValidationConfig{
			SecretRef: isovalentv1alpha1.LBServiceSecretRef{
				Name: clientCertSecretName,
			},
		}

		if err := ciliumCli.UpdateLBService(ctx, ns, curSvc, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("failed to update LB service (%s): %s", testName, err)
		}

		testCmd := curlCmdVerbose(fmt.Sprintf("--max-time 1 --cert /tmp/%s.crt --key /tmp/%s.key --cacert /tmp/%s.crt --resolve secure.acme.io:10443:%s https://secure.acme.io:10443/",
			clientHostName, clientHostName, serviceHostName, vipIP))

		t.Logf("Testing %q...", testCmd)

		eventually(t, func() error {
			stdout, stderr, err := dockerCli.clientExec(ctx, clientName, testCmd)
			if err != nil {
				// Enrich error with curl output
				return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
			}
			return nil
		}, 10*time.Second, 100*time.Millisecond)
	})
}
