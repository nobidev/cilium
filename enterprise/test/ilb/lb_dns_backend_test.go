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

func TestDNSBackend(t *testing.T) {
	ctx := context.Background()
	testNameBase := "dns-backend"
	testK8sNamespace := "default"

	ciliumCli, k8sCli := newCiliumAndK8sCli(t)
	dockerCli := newDockerCli(t)

	t.Log("Creating backend apps...")

	tests := []struct {
		name           string
		suffix         string
		serviceHost    string
		serviceOptions []serviceOption
		serviceTLS     bool
		backendTLS     bool
	}{
		{
			name:        "HTTPProxy",
			suffix:      "-http-proxy",
			serviceHost: "insecure.acme.io",
			serviceOptions: []serviceOption{
				withPort(80),
				withHTTPProxyApplication(withHttpRoute(testNameBase + "-http-proxy")),
			},
		},
		{
			name:        "HTTPSProxy",
			suffix:      "-https-proxy",
			serviceHost: "secure.acme.io",
			serviceOptions: []serviceOption{
				withPort(443),
				withHTTPSProxyApplication(
					withHttpsRoute(testNameBase+"-https-proxy"),
					withCertificate(testNameBase+"-https-proxy"),
				),
			},
			serviceTLS: true,
		},
		{
			name:        "TLSPassthrough",
			suffix:      "-tls-passthrough",
			serviceHost: "secure-backend.acme.io",
			serviceOptions: []serviceOption{
				withPort(443),
				withTLSPassthroughApplication(
					withTLSPassthroughRoute(testNameBase + "-tls-passthrough"),
				),
			},
			serviceTLS: true,
			backendTLS: true,
		},
		{
			name:        "TLSProxy",
			suffix:      "-tls-proxy",
			serviceHost: "secure.acme.io",
			serviceOptions: []serviceOption{
				withPort(443),
				withTLSProxyApplication(
					withTLSCertificate(testNameBase+"-tls-proxy"),
					withTLSProxyRoute(testNameBase+"-tls-proxy", withHostname("secure.acme.io")),
				),
			},
			serviceTLS: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testName := testNameBase + tt.suffix
			backendHostName := fmt.Sprintf("backend.%s.local", testName)

			scenario := newLBTestScenario(t, testName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

			t.Log("Creating backend apps...")

			// FIXME: In the single node mode, we cannot bind two or more backends
			// to the same name because the port number of the backends are
			// different and DNS-based backend cannot tell the port number
			// (possibly, SRV record, but Envoy doesn't support it as of
			// 2024-10-07). So, we only create only one backend in the single node
			// mode. Better than testing nothing.
			var nbackends int
			if isSingleNode() {
				nbackends = 1
			} else {
				nbackends = 2
			}

			var beContainers []*hcAppContainer
			if tt.backendTLS {
				scenario.createBackendServerCertificate(ctx, backendHostName)
				beContainers = scenario.addBackendApplications(ctx, nbackends, backendApplicationConfig{
					tlsCertHostname: backendHostName,
				})
			} else {
				beContainers = scenario.addBackendApplications(ctx, nbackends, backendApplicationConfig{
					h2cEnabled: true,
				})
			}

			t.Log("Registering backend apps in CoreDNS...")
			coredns := scenario.addCoreDNS(ctx)

			records := []*coreDNSRecord{}
			for _, be := range beContainers {
				records = append(records, &coreDNSRecord{
					Hostname: "backend",
					IP:       be.ip,
				})
			}
			if err := coredns.AddDNSRecords(ctx, records); err != nil {
				t.Fatalf("failed to add DNS records: %v", err)
			}

			t.Log("Creating clients and add BGP peering ...")
			client := scenario.addFRRClients(ctx, 1, frrClientConfig{})[0]

			t.Logf("Creating LB VIP resources...")
			vip := lbVIP(testK8sNamespace, testName)
			scenario.createLBVIP(ctx, vip)

			t.Logf("Creating LB BackendPool resources...")
			var backendPool *isovalentv1alpha1.LBBackendPool
			if tt.backendTLS {
				backendPool = lbBackendPool(testK8sNamespace, testName,
					withHostnameBackend(backendHostName, 8080),
					withDNSResolver(coredns.ip, coredns.port),
					withHealthCheckTLS(),
				)
			} else {
				backendPool = lbBackendPool(testK8sNamespace, testName,
					withHostnameBackend(backendHostName, 8080),
					withDNSResolver(coredns.ip, coredns.port),
				)
			}
			scenario.createLBBackendPool(ctx, backendPool)

			t.Logf("Creating LB Service resources...")
			if tt.serviceTLS {
				// Server certificate
				scenario.createLBServerCertificate(ctx, testName, "secure.acme.io")
			}

			service := lbService(testK8sNamespace, testName, tt.serviceOptions...)
			scenario.createLBService(ctx, service)
			svcPort := service.Spec.Port

			t.Logf("Waiting for full VIP connectivity of %q...", vip.Name)
			vipIP := scenario.waitForFullVIPConnectivity(ctx, vip.Name)

			var testCmd string
			if tt.serviceTLS {
				testCmd = curlCmd(fmt.Sprintf(`-k -m 5 -H "Content-Type: application/json" --resolve %s:%d:%s https://%s:%d/`, tt.serviceHost, svcPort, vipIP, tt.serviceHost, svcPort))
			} else {
				testCmd = curlCmd(fmt.Sprintf(`-m 5 -H "Content-Type: application/json" --resolve %s:%d:%s http://%s:%d/`, tt.serviceHost, svcPort, vipIP, tt.serviceHost, svcPort))
			}

			observedBackends := make(map[string]struct{})
			eventually(t, func() error {
				stdout, stderr, err := client.Exec(ctx, testCmd)
				if err != nil {
					return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
				}

				resp := toTestAppResponse(t, stdout)
				observedBackends[resp.InstanceName] = struct{}{}

				if len(observedBackends) != nbackends {
					return fmt.Errorf("have not observed all backends yet: %d/%d", len(observedBackends), nbackends)
				}

				return nil
			}, shortTimeout, pollInterval)
		})
	}
}
