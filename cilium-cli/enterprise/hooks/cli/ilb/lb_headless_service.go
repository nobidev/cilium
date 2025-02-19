// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package ilb

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8s "github.com/cilium/cilium/pkg/k8s/slim/k8s/clientset"
)

func backendDeployment(name string, replicas int32, config backendApplicationConfig) *appsv1.Deployment {
	envs := []corev1.EnvVar{
		{
			Name:  "SERVICE_NAME",
			Value: name,
		},
		{
			Name: "INSTANCE_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.name",
				},
			},
		},
	}
	if config.h2cEnabled {
		envs = append(envs, corev1.EnvVar{
			Name:  "H2C_ENABLED",
			Value: "true",
		})
	}
	if config.tlsCertHostname != "" {
		// It is ok to just generate a self-signed cert here and don't share
		// it with the client. The client will not verify the cert.
		key, cert, err := genSelfSignedX509(config.tlsCertHostname)
		if err != nil {
			fatalf("failed to gen x509: %s", err)
		}
		envs = append(envs, corev1.EnvVar{
			Name:  "TLS_ENABLED",
			Value: "true",
		})
		envs = append(envs, corev1.EnvVar{
			Name:  "TLS_KEY_BASE64",
			Value: base64.StdEncoding.EncodeToString(key.Bytes()),
		})
		envs = append(envs, corev1.EnvVar{
			Name:  "TLS_CERT_BASE64",
			Value: base64.StdEncoding.EncodeToString(cert.Bytes()),
		})
	}
	if config.listenPort != 0 {
		envs = append(envs, corev1.EnvVar{
			Name:  "LISTEN_ADDRESS",
			Value: fmt.Sprintf(":%d", config.listenPort),
		})
	}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"app": name,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(replicas),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": name,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": name,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "healthcheck",
							Image: FlagAppImage,
							Env:   envs,
						},
					},
				},
			},
		},
	}
}

func backendService(name string, port int32) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "None",
			Selector: map[string]string{
				"app": name,
			},
			Ports: []corev1.ServicePort{
				{
					Protocol: corev1.ProtocolTCP,
					Port:     port,
				},
			},
		},
	}
}

func createAndWaitHeadlessServiceBackends(k8sCli *k8s.Clientset, namespace, name string, replicas int32, tls bool) *corev1.PodList {
	var deployment *appsv1.Deployment

	if tls {
		deployment = backendDeployment(name, replicas, backendApplicationConfig{
			tlsCertHostname: "secure-backend.acme.io",
		})
	} else {
		deployment = backendDeployment(name, replicas, backendApplicationConfig{
			h2cEnabled: true,
		})
	}

	if _, err := k8sCli.AppsV1().Deployments(namespace).Create(context.Background(), deployment, metav1.CreateOptions{}); err != nil {
		fatalf("failed to create deployment (%s): %s", deployment.Name, err)
	}
	MaybeCleanupT(func() error {
		return k8sCli.AppsV1().Deployments(namespace).Delete(context.Background(), deployment.Name, metav1.DeleteOptions{})
	})

	service := backendService(name, 8080)
	if _, err := k8sCli.CoreV1().Services(namespace).Create(context.Background(), service, metav1.CreateOptions{}); err != nil {
		fatalf("failed to create service (%s): %s", service.Name, err)
	}
	MaybeCleanupT(func() error {
		return k8sCli.CoreV1().Services(namespace).Delete(context.Background(), service.Name, metav1.DeleteOptions{})
	})

	watch, err := k8sCli.AppsV1().Deployments(namespace).Watch(context.Background(), metav1.ListOptions{
		LabelSelector: "app=" + name,
	})
	if err != nil {
		fatalf("failed to watch deployment (%s): %s", name, err)
	}
	defer watch.Stop()

	timeout := time.After(longTimeout)

	for {
		var completed bool
		select {
		case ev := <-watch.ResultChan():
			deploy, ok := ev.Object.(*appsv1.Deployment)
			if !ok {
				fatalf("unexpected object type: %T", ev.Object)
			}
			if deploy.Name != name {
				continue
			}
			if deploy.Status.ReadyReplicas != replicas {
				continue
			}
			completed = true
		case <-timeout:
			fatalf("timed out waiting for deployment (%s)", name)
		}
		if completed {
			break
		}
	}

	pods, err := k8sCli.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "app=" + name,
	})
	if err != nil {
		fatalf("failed to list pods (%s): %s", name, err)
	}

	return pods
}

func TestHeadlessService() {
	if skipIfOnSingleNode("DNS backend test uses k8s-based backend services which is not supported in single-node mode") {
		return
	}

	fmt.Println("=== RUN   TestBasicAuth")

	ctx := context.Background()
	testName := "headless-service"
	testK8sNamespace := "default"
	backendReplicas := int32(2)

	ciliumCli, k8sCli := NewCiliumAndK8sCli()
	dockerCli := NewDockerCli()

	tcpName := testName + "-tcp"
	tlsName := testName + "-tls"
	tcpBackendHostName := fmt.Sprintf("%s.%s.svc.cluster.local", tcpName, testK8sNamespace)
	tlsBackendHostName := fmt.Sprintf("%s.%s.svc.cluster.local", tlsName, testK8sNamespace)

	fmt.Println("Creating backend apps...")
	tcpBackends := createAndWaitHeadlessServiceBackends(k8sCli, testK8sNamespace, tcpName, backendReplicas, false)
	tlsBackends := createAndWaitHeadlessServiceBackends(k8sCli, testK8sNamespace, tlsName, backendReplicas, true)

	tests := []struct {
		name            string
		suffix          string
		serviceHost     string
		backendHost     string
		serviceOptions  []serviceOption
		serviceTLS      bool
		backendTLS      bool
		desiredBackends *corev1.PodList
	}{
		{
			name:        "HTTPProxy",
			suffix:      "-http-proxy",
			serviceHost: "insecure.acme.io",
			backendHost: tcpBackendHostName,
			serviceOptions: []serviceOption{
				withPort(80),
				withHTTPProxyApplication(withHttpRoute(testName + "-http-proxy")),
			},
			desiredBackends: tcpBackends,
		},
		{
			name:        "HTTPSProxy",
			suffix:      "-https-proxy",
			serviceHost: "secure.acme.io",
			backendHost: tcpBackendHostName,
			serviceOptions: []serviceOption{
				withPort(443),
				withHTTPSProxyApplication(
					withHttpsRoute(testName+"-https-proxy"),
					withCertificate(testName+"-https-proxy"),
				),
			},
			serviceTLS:      true,
			desiredBackends: tcpBackends,
		},
		{
			name:        "TLSPassthrough",
			suffix:      "-tls-passthrough",
			serviceHost: "secure-backend.acme.io",
			backendHost: tlsBackendHostName,
			serviceOptions: []serviceOption{
				withPort(443),
				withTLSPassthroughApplication(withTLSPassthroughRoute(testName + "-tls-passthrough")),
			},
			serviceTLS:      true,
			backendTLS:      true,
			desiredBackends: tlsBackends,
		},
		{
			name:        "TLSProxy",
			suffix:      "-tls-proxy",
			serviceHost: "secure.acme.io",
			backendHost: tcpBackendHostName,
			serviceOptions: []serviceOption{
				withPort(443),
				withTLSProxyApplication(withTLSCertificate(testName+"-tls-proxy"), withTLSProxyRoute(testName+"-tls-proxy", withHostname("secure.acme.io"))),
			},
			serviceTLS:      true,
			desiredBackends: tcpBackends,
		},
	}

	for _, tt := range tests {
		fmt.Printf("=== RUN   TestBasicAuth/%s\n", tt.name)

		resourceName := testName + tt.suffix

		scenario := newLBTestScenario(resourceName, testK8sNamespace, ciliumCli, k8sCli, dockerCli)

		fmt.Println("Creating clients and add BGP peering ...")
		client := scenario.addFRRClients(ctx, 1, frrClientConfig{})[0]

		fmt.Println("Creating LB VIP resources...")
		vip := lbVIP(testK8sNamespace, resourceName)
		scenario.createLBVIP(ctx, vip)

		fmt.Println("Creating LB BackendPool resources...")
		var backendPool *isovalentv1alpha1.LBBackendPool
		if tt.backendTLS {
			backendPool = lbBackendPool(testK8sNamespace, resourceName,
				withHostnameBackend(tlsBackendHostName, 8080),
				withHealthCheckTLS(),
			)
		} else {
			backendPool = lbBackendPool(testK8sNamespace, resourceName,
				withHostnameBackend(tcpBackendHostName, 8080),
			)
		}
		scenario.createLBBackendPool(ctx, backendPool)

		fmt.Println("Creating LB Service resources...")
		if tt.serviceTLS {
			// Server certificate
			scenario.createLBServerCertificate(ctx, resourceName, "secure.acme.io")
		}

		service := lbService(testK8sNamespace, resourceName, tt.serviceOptions...)
		scenario.createLBService(ctx, service)
		svcPort := service.Spec.Port

		maybeSysdump(testName, tt.suffix)

		fmt.Printf("Waiting for full VIP connectivity of %q...\n", vip.Name)
		vipIP := scenario.waitForFullVIPConnectivity(ctx, vip.Name)

		var testCmd string
		if tt.serviceTLS {
			testCmd = curlCmd(fmt.Sprintf("-k --max-time 10 -H 'Content-Type: application/json' --resolve %s:%d:%s https://%s:%d/", tt.serviceHost, svcPort, vipIP, tt.serviceHost, svcPort))
		} else {
			testCmd = curlCmd(fmt.Sprintf("--max-time 10 -H 'Content-Type: application/json' --resolve %s:%d:%s http://%s:%d/", tt.serviceHost, svcPort, vipIP, tt.serviceHost, svcPort))
		}

		fmt.Printf("Testing %q until observing response from all backends bound to %s\n", testCmd, tt.backendHost)

		observedBackends := make(map[string]struct{})
		eventually(func() error {
			stdout, stderr, err := client.Exec(ctx, testCmd)
			if err != nil {
				return fmt.Errorf("curl failed (cmd: %q, stdout: %q, stderr: %q): %w", testCmd, stdout, stderr, err)
			}

			// Response from the health check server contains instance name (Pod name in this case)
			appResponse := toTestAppResponse(stdout)

			for _, pod := range tt.desiredBackends.Items {
				if appResponse.InstanceName == pod.Name {
					observedBackends[pod.Name] = struct{}{}
				}
			}

			// Check if we have observed all backends
			if len(observedBackends) != int(backendReplicas) {
				return fmt.Errorf("have not observed all backends yet: %d/%d", len(observedBackends), backendReplicas)
			}

			return nil
		}, shortTimeout, pollInterval)
	}
}
