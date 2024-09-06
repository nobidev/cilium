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
	"encoding/base64"
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8s "github.com/cilium/cilium/pkg/k8s/slim/k8s/clientset"
)

type lbTestScenario struct {
	t *testing.T

	testName     string
	k8sNamespace string

	ciliumCli *ciliumCli
	k8sCli    *k8s.Clientset
	dockerCli *dockerCli

	backendApps         map[string]*dockerContainer
	frrClients          map[string]*dockerContainer
	serverCertificates  map[string]*tlsCertificate
	backendCertificates map[string]*tlsCertificate
}

type dockerContainer struct {
	id string
	ip string
}

type tlsCertificate struct {
	cert       []byte
	key        []byte
	certBase64 string
	keyBase64  string
}

func newLBTestScenario(t *testing.T, testName string, k8sNamespace string, ciliumCli *ciliumCli, k8sCli *k8s.Clientset, dockerCli *dockerCli) *lbTestScenario {
	return &lbTestScenario{
		t:                   t,
		testName:            testName,
		k8sNamespace:        k8sNamespace,
		ciliumCli:           ciliumCli,
		k8sCli:              k8sCli,
		dockerCli:           dockerCli,
		backendApps:         map[string]*dockerContainer{},
		frrClients:          map[string]*dockerContainer{},
		serverCertificates:  map[string]*tlsCertificate{},
		backendCertificates: map[string]*tlsCertificate{},
	}
}

func (r *lbTestScenario) waitForFullVIPConnectivity(ctx context.Context) string {
	ip, err := r.ciliumCli.WaitForLBVIP(ctx, r.k8sNamespace, r.testName)
	if err != nil {
		r.t.Fatalf("failed to wait for VIP (%s): %s", r.testName, err)
	}

	for cName, c := range r.frrClients {
		err = r.dockerCli.waitForIPRoute(ctx, c.id, ip)
		if err != nil {
			r.t.Fatalf("failed to wait for IP route in client (%s): %s", cName, err)
		}
	}

	return ip
}

func (r *lbTestScenario) addBackendApplications(ctx context.Context, numberOfBackends int, config backendApplicationConfig) {
	startIndex := len(r.backendApps)

	for i := startIndex; i < startIndex+numberOfBackends; i++ {
		appName := fmt.Sprintf("%s-app-%d", r.testName, i)
		envVars := r.getBackendApplicationEnvVars(appName, config)

		id, ip, err := r.dockerCli.createContainer(ctx, appName, appImage, envVars, containerNetwork, false)
		if err != nil {
			r.t.Fatalf("cannot create app container (%s): %s", appName, err)
		}

		r.backendApps[appName] = &dockerContainer{
			id: id,
			ip: ip,
		}

		maybeCleanupT(func() error { return r.dockerCli.deleteContainer(context.Background(), id) }, r.t)
	}
}

func (r *lbTestScenario) getBackendApplicationEnvVars(appName string, config backendApplicationConfig) []string {
	env := []string{
		"SERVICE_NAME=" + appName,
		"INSTANCE_NAME=" + appName,
	}

	if config.h2cEnabled {
		env = append(env, "H2C_ENABLED=true")
	}

	if len(config.tlsCertHostname) > 0 {
		cert, ok := r.backendCertificates[config.tlsCertHostname]
		if !ok {
			r.t.Fatalf("backend certificate with hostname %q not found", config.tlsCertHostname)
		}

		env = append(env, "TLS_ENABLED=true")
		env = append(env, "TLS_KEY_BASE64="+cert.keyBase64)
		env = append(env, "TLS_CERT_BASE64="+cert.certBase64)
	}

	return env
}

type backendApplicationConfig struct {
	h2cEnabled      bool
	tlsCertHostname string
}

func (r *lbTestScenario) addFRRClients(ctx context.Context, numberOfClients int, config frrClientConfig) {
	startIndex := len(r.frrClients)

	for i := startIndex; i < startIndex+numberOfClients; i++ {
		clientName := fmt.Sprintf("%s-client-%d", r.testName, i)
		env := []string{
			"NEIGHBORS=" + getBGPNeighborString(r.t, r.dockerCli),
		}

		id, ip, err := r.dockerCli.createContainer(ctx, clientName, clientImage, env, containerNetwork, true)
		if err != nil {
			r.t.Fatalf("cannot create frr client container (%s): %s", clientName, err)
		}

		r.frrClients[clientName] = &dockerContainer{
			id: id,
			ip: ip,
		}

		maybeCleanupT(func() error { return r.dockerCli.deleteContainer(context.Background(), id) }, r.t)

		if err := r.ciliumCli.doBGPPeeringForClient(ctx, ip); err != nil {
			r.t.Fatalf("failed to BGP peer (%s): %s", clientName, err)
		}
		maybeCleanupT(func() error { return r.ciliumCli.undoBGPPeeringForClient(context.Background(), ip) }, r.t)

		for _, h := range config.trustedCertsHostnames {
			sc, serverCertFound := r.serverCertificates[h]
			if !serverCertFound {
				bc, backendCertFound := r.backendCertificates[h]
				if !backendCertFound {
					r.t.Fatalf("certificate for hostname %q doesn't exist", h)
				}
				sc = bc
			}

			if err := r.dockerCli.copyToContainer(ctx, id, sc.cert, h+".crt", "/tmp"); err != nil {
				r.t.Fatalf("failed to copy cert to client container: %s", err)
			}
		}

	}
}

type frrClientConfig struct {
	trustedCertsHostnames []string
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

func (r *lbTestScenario) createServerCertificate(ctx context.Context, hostName string) {
	key, cert, err := genSelfSignedX509(hostName)
	if err != nil {
		r.t.Fatalf("failed to gen x509: %s", err)
	}

	sec := secret(r.k8sNamespace, r.testName, key.Bytes(), cert.Bytes())
	if _, err := r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Create(ctx, sec, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			r.t.Fatalf("failed to create secret (%s): %s", r.testName, err)
		}
	}

	certBytes := cert.Bytes()
	keyBytes := key.Bytes()
	r.serverCertificates[hostName] = &tlsCertificate{
		cert:       certBytes,
		key:        keyBytes,
		certBase64: base64.StdEncoding.EncodeToString(certBytes),
		keyBase64:  base64.StdEncoding.EncodeToString(keyBytes),
	}

	maybeCleanupT(func() error {
		return r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Delete(ctx, r.testName, metav1.DeleteOptions{})
	}, r.t)
}

func (r *lbTestScenario) createBackendCertificate(_ context.Context, hostName string) {
	key, cert, err := genSelfSignedX509(hostName)
	if err != nil {
		r.t.Fatalf("failed to gen x509: %s", err)
	}

	certBytes := cert.Bytes()
	keyBytes := key.Bytes()
	r.backendCertificates[hostName] = &tlsCertificate{
		cert:       certBytes,
		key:        keyBytes,
		certBase64: base64.StdEncoding.EncodeToString(certBytes),
		keyBase64:  base64.StdEncoding.EncodeToString(keyBytes),
	}
}
