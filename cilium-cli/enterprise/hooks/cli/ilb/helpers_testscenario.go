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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"

	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	metaslimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8s "github.com/cilium/cilium/pkg/k8s/slim/k8s/clientset"
)

type lbTestScenario struct {
	testName     string
	k8sNamespace string

	ciliumCli *ciliumCli
	k8sCli    *k8s.Clientset
	dockerCli *dockerCli

	coreDNSContainer *coreDNSContainer
	nginxContainer   *nginxContainer

	backendApps         map[string]*hcAppContainer
	frrClients          map[string]*frrContainer
	serverCertificates  map[string]*tlsCertificate
	backendCertificates map[string]*tlsCertificate
	clientCertificates  map[string]*tlsCertificate
}

type tlsCertificate struct {
	cert       []byte
	key        []byte
	certBase64 string
	keyBase64  string
}

func newLBTestScenario(testName string, k8sNamespace string, ciliumCli *ciliumCli, k8sCli *k8s.Clientset, dockerCli *dockerCli) *lbTestScenario {
	return &lbTestScenario{
		testName:            testName,
		k8sNamespace:        k8sNamespace,
		ciliumCli:           ciliumCli,
		k8sCli:              k8sCli,
		dockerCli:           dockerCli,
		coreDNSContainer:    nil,
		backendApps:         map[string]*hcAppContainer{},
		frrClients:          map[string]*frrContainer{},
		serverCertificates:  map[string]*tlsCertificate{},
		backendCertificates: map[string]*tlsCertificate{},
		clientCertificates:  map[string]*tlsCertificate{},
	}
}

func (r *lbTestScenario) waitForFullVIPConnectivity(ctx context.Context, vipName string) string {
	ip, err := r.ciliumCli.WaitForLBVIP(ctx, r.k8sNamespace, vipName)
	if err != nil {
		fatalf("failed to wait for VIP (%s): %s", vipName, err)
	}

	for _, c := range r.frrClients {
		eventually(func() error {
			return c.EnsureRoute(ctx, ip+"/32")
		}, longTimeout, pollInterval)
	}

	return ip
}

func (r *lbTestScenario) addCoreDNS(ctx context.Context) *coreDNSContainer {
	if r.coreDNSContainer != nil {
		return r.coreDNSContainer
	}

	name := fmt.Sprintf("%s-coredns", r.testName)

	// We must create an initial file before starting the container. Otherwise,
	// CoreDNS uses on-memory default configuration and we cannot update it later.
	preStart := func(c *dockerCli, id string) error {
		return c.copyToContainer(ctx, id, []byte(". {}"), "Corefile", "/tmp")
	}

	// Override the default port to avoid colliding with the rest of the system
	id, ip, err := r.dockerCli.createContainer(ctx, name, FlagCoreDNSImage, nil, containerNetwork, false, []string{"-conf", "/tmp/Corefile", "-dns.port", "10053"}, preStart)
	if err != nil {
		fatalf("cannot create CoreDNS container: %s", err)
	}

	container := &coreDNSContainer{
		dockerContainer: dockerContainer{
			id:        id,
			ip:        ip,
			port:      10053,
			dockerCli: r.dockerCli,
		},
		// All the records will be under <testName>.local domain
		Domain: r.testName + ".local",
	}

	r.coreDNSContainer = container

	RegisterMaybeCleanupAfterTest(func() error { return r.dockerCli.deleteContainer(context.Background(), id) })

	return container
}

func (r *lbTestScenario) addNginx(ctx context.Context) *nginxContainer {
	if r.nginxContainer != nil {
		return r.nginxContainer
	}

	name := fmt.Sprintf("%s-nginx", r.testName)

	id, ip, err := r.dockerCli.createContainer(ctx, name, FlagNginxImage, nil, containerNetwork, false, nil, nil)
	if err != nil {
		fatalf("cannot create Nginx container: %s", err)
	}

	container := &nginxContainer{
		dockerContainer: dockerContainer{
			id:        id,
			ip:        ip,
			port:      18080,
			dockerCli: r.dockerCli,
		},
	}

	r.nginxContainer = container

	RegisterMaybeCleanupAfterTest(func() error { return r.dockerCli.deleteContainer(context.Background(), id) })

	return container
}

func (r *lbTestScenario) addBackendApplications(ctx context.Context, numberOfBackends int, config backendApplicationConfig) []*hcAppContainer {
	containers := []*hcAppContainer{}
	startIndex := len(r.backendApps)

	if config.listenPort == 0 {
		config.listenPort = 8080
	}

	for i := startIndex; i < startIndex+numberOfBackends; i++ {
		appName := fmt.Sprintf("%s-app-%d", r.testName, i)
		envVars := r.getBackendApplicationEnvVars(appName, config)

		id, ip, err := r.dockerCli.createContainer(ctx, appName, FlagAppImage, envVars, containerNetwork, false, nil, nil)
		if err != nil {
			fatalf("cannot create app container (%s): %s", appName, err)
		}

		container := &hcAppContainer{
			dockerContainer: dockerContainer{
				id:        id,
				ip:        ip,
				port:      config.listenPort,
				dockerCli: r.dockerCli,
			},
			config: config,
		}

		r.backendApps[appName] = container

		containers = append(containers, container)

		if IsSingleNode() {
			// On the single node all containers are deployed in the host
			// netns. To avoid port collisions, we keep +1 for each instance.
			config.listenPort++
		}

		RegisterMaybeCleanupAfterTest(func() error { return r.dockerCli.deleteContainer(context.Background(), id) })
	}

	return containers
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
			fatalf("backend certificate with hostname %q not found", config.tlsCertHostname)
		}

		env = append(env, "TLS_ENABLED=true")
		env = append(env, "TLS_KEY_BASE64="+cert.keyBase64)
		env = append(env, "TLS_CERT_BASE64="+cert.certBase64)
	}

	if config.listenPort != 0 {
		env = append(env, fmt.Sprintf("LISTEN_ADDRESS=:%d", config.listenPort))
	}

	return env
}

func (r *lbTestScenario) addFRRClients(ctx context.Context, numberOfClients int, config frrClientConfig) []*frrContainer {
	containers := []*frrContainer{}
	startIndex := len(r.frrClients)

	// Lazily create the per-scenario BGP-related resources here. Calling
	// addFRRClients multiple times will not create multiple resource. The
	// resources created in the first call will be reused.
	r.createBGPPeerConfig(ctx)
	r.createBFDProfile(ctx)

	for i := startIndex; i < startIndex+numberOfClients; i++ {
		clientName := fmt.Sprintf("%s-client-%d", r.testName, i)
		env := []string{
			"NEIGHBORS=" + getBGPNeighborString(r.k8sCli),
		}

		id, ip, err := r.dockerCli.createContainer(ctx, clientName, FlagClientImage, env, containerNetwork, true, nil, nil)
		if err != nil {
			fatalf("cannot create frr client container (%s): %s", clientName, err)
		}

		container := &frrContainer{
			dockerContainer: dockerContainer{
				id:        id,
				ip:        ip,
				dockerCli: r.dockerCli,
			},
		}

		r.frrClients[clientName] = container

		containers = append(containers, container)

		RegisterMaybeCleanupAfterTest(func() error { return r.dockerCli.deleteContainer(context.Background(), id) })

		for _, h := range config.trustedCertsHostnames {
			sc, serverCertFound := r.serverCertificates[h]
			if !serverCertFound {
				bc, backendCertFound := r.backendCertificates[h]
				if !backendCertFound {
					fatalf("certificate for hostname %q doesn't exist", h)
				}
				sc = bc
			}

			if err := container.Copy(ctx, sc.cert, h+".crt", "/tmp"); err != nil {
				fatalf("failed to copy cert to client container: %s", err)
			}
		}

		for hostName, cert := range r.clientCertificates {
			if err := container.Copy(ctx, cert.cert, hostName+".crt", "/tmp"); err != nil {
				fatalf("failed to copy cert to client container: %s", err)
			}
			if err := container.Copy(ctx, cert.key, hostName+".key", "/tmp"); err != nil {
				fatalf("failed to copy key to client container: %s", err)
			}
		}

		// Make BGP peering with T1 nodes
		if err := r.doBGPPeeringForClient(ctx, clientName, ip); err != nil {
			fatalf("failed to BGP peer (%s): %s", clientName, err)
		}
		RegisterMaybeCleanupAfterTest(func() error { return r.undoBGPPeeringForClient(context.Background(), ip) })
	}

	return containers
}

func (r *lbTestScenario) createBGPPeerConfig(ctx context.Context) {
	obj := &isovalentv1alpha1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: r.testName,
		},
		Spec: isovalentv1alpha1.IsovalentBGPPeerConfigSpec{
			CiliumBGPPeerConfigSpec: ciliumv2alpha1.CiliumBGPPeerConfigSpec{
				Families: []ciliumv2alpha1.CiliumBGPFamilyWithAdverts{
					{
						CiliumBGPFamily: ciliumv2alpha1.CiliumBGPFamily{
							Afi:  "ipv4",
							Safi: "unicast",
						},
						// Assuming the advertisement will be created with the label with scenario name
						Advertisements: &metaslimv1.LabelSelector{
							MatchLabels: map[string]metaslimv1.MatchLabelsValue{
								"scenario": r.testName,
							},
						},
					},
				},
				Timers: &ciliumv2alpha1.CiliumBGPTimers{
					ConnectRetryTimeSeconds: ptr.To(int32(1)),
				},
			},
			BFDProfileRef: ptr.To(r.testName),
		},
	}
	if _, err := r.ciliumCli.IsovalentV1alpha1().IsovalentBGPPeerConfigs().Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			fatalf("failed to create Peer config (%s): %s", obj.Name, err)
		}
	}
	RegisterMaybeCleanupAfterTest(func() error {
		return r.ciliumCli.IsovalentV1alpha1().IsovalentBGPPeerConfigs().Delete(ctx, obj.Name, metav1.DeleteOptions{})
	})
}

func (r *lbTestScenario) createBFDProfile(ctx context.Context) {
	obj := &isovalentv1alpha1.IsovalentBFDProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: r.testName,
		},
		Spec: isovalentv1alpha1.BFDProfileSpec{
			DetectMultiplier:             ptr.To(int32(3)),
			ReceiveIntervalMilliseconds:  ptr.To(int32(300)),
			TransmitIntervalMilliseconds: ptr.To(int32(300)),
		},
	}
	if _, err := r.ciliumCli.IsovalentV1alpha1().IsovalentBFDProfiles().Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			fatalf("failed to create BFD profile (%s): %s", obj.Name, err)
		}
	}
	RegisterMaybeCleanupAfterTest(func() error {
		return r.ciliumCli.IsovalentV1alpha1().IsovalentBFDProfiles().Delete(context.Background(), obj.Name, metav1.DeleteOptions{})
	})
}

func (r *lbTestScenario) createBGPAdvertisement(ctx context.Context, vipName string) {
	// BGP Advertisement has a one-to-one mapping with the VIP
	obj := &isovalentv1alpha1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: vipName,
			// This label is referenced in the BGPPeerConfig
			Labels: map[string]string{
				"scenario": r.testName,
			},
		},
		Spec: isovalentv1alpha1.IsovalentBGPAdvertisementSpec{
			Advertisements: []isovalentv1alpha1.BGPAdvertisement{
				{
					AdvertisementType: isovalentv1alpha1.BGPServiceAdvert,
					Service: &isovalentv1alpha1.BGPServiceOptions{
						Addresses: []ciliumv2alpha1.BGPServiceAddressType{
							ciliumv2alpha1.BGPLoadBalancerIPAddr,
						},
					},
					Selector: &metaslimv1.LabelSelector{
						MatchExpressions: []metaslimv1.LabelSelectorRequirement{
							{
								Key:      "loadbalancer.isovalent.com/vip-name",
								Operator: metaslimv1.LabelSelectorOpIn,
								Values:   []string{vipName},
							},
						},
					},
				},
			},
		},
	}
	if _, err := r.ciliumCli.IsovalentV1alpha1().IsovalentBGPAdvertisements().Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			fatalf("failed to create BGP advertisement (%s): %s", obj.Name, err)
		}
	}
	RegisterMaybeCleanupAfterTest(func() error {
		return r.ciliumCli.IsovalentV1alpha1().IsovalentBGPAdvertisements().Delete(ctx, obj.Name, metav1.DeleteOptions{})
	})
}

// Fixed interval with jitter. Jittered, but fixed (non-exponential) interval
// backoff up to 5 times.
var bgpUpdateBackoff = wait.Backoff{
	Duration: time.Second,
	Factor:   1.0,
	Jitter:   1.0,
	Steps:    5,
	Cap:      time.Second * 2, // This backoff will never hit the cap
}

func (r *lbTestScenario) doBGPPeeringForClient(ctx context.Context, name string, clientIP string) error {
	return retry.RetryOnConflict(bgpUpdateBackoff, func() error {
		cc, err := r.ciliumCli.IsovalentV1alpha1().IsovalentBGPClusterConfigs().Get(ctx, globalBGPClusterConfigName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get BGP cluster config (%s): %w", globalBGPClusterConfigName, err)
		}

		cc.Spec.BGPInstances[0].Peers = append(cc.Spec.BGPInstances[0].Peers,
			isovalentv1alpha1.IsovalentBGPPeer{
				Name:        "peer-" + clientIP,
				PeerAddress: &clientIP,
				PeerASN:     ptr.To[int64](64512),
				PeerConfigRef: &isovalentv1alpha1.PeerConfigReference{
					Name: r.testName,
				},
			})

		if _, err := r.ciliumCli.IsovalentV1alpha1().IsovalentBGPClusterConfigs().Update(ctx, cc, metav1.UpdateOptions{}); err != nil {
			// According to the document of retry.RetryOnConflict
			// > You have to return err itself here (not wrapped inside another error)
			// > so that RetryOnConflict can identify it correctly.
			return err
		}

		return nil
	})
}

func (r *lbTestScenario) undoBGPPeeringForClient(ctx context.Context, clientIP string) error {
	return retry.RetryOnConflict(bgpUpdateBackoff, func() error {
		cc, err := r.ciliumCli.IsovalentV1alpha1().IsovalentBGPClusterConfigs().Get(ctx, globalBGPClusterConfigName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get BGP cluster config (%s): %w", globalBGPClusterConfigName, err)
		}

		peers := cc.Spec.BGPInstances[0].Peers

		updatedPeers := []isovalentv1alpha1.IsovalentBGPPeer{}
		for _, peer := range peers {
			if *peer.PeerAddress != clientIP {
				updatedPeers = append(updatedPeers, peer)
			}
		}

		cc.Spec.BGPInstances[0].Peers = updatedPeers
		if _, err := r.ciliumCli.IsovalentV1alpha1().IsovalentBGPClusterConfigs().Update(ctx, cc, metav1.UpdateOptions{}); err != nil {
			// According to the document of retry.RetryOnConflict
			// > You have to return err itself here (not wrapped inside another error)
			// > so that RetryOnConflict can identify it correctly.
			return err
		}

		return nil
	})
}

type frrClientConfig struct {
	trustedCertsHostnames []string
}

// createLBVIP creates the LBVIP
// In addition, BGP peering is established for the VIP to all existing clients.
func (r *lbTestScenario) createLBVIP(ctx context.Context, vip *isovalentv1alpha1.LBVIP) {
	if err := r.ciliumCli.CreateLBVIP(ctx, r.k8sNamespace, vip, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			fatalf("cannot create LB VIP (%s): %s", r.testName, err)
		}
	}
	RegisterMaybeCleanupAfterTest(func() error {
		return r.ciliumCli.DeleteLBVIP(ctx, vip.Namespace, vip.Name, metav1.DeleteOptions{})
	})

	// Create BGPAdvertisement corresponding to the VIP
	r.createBGPAdvertisement(ctx, vip.Name)
}

func (r *lbTestScenario) createLBBackendPool(ctx context.Context, bp *isovalentv1alpha1.LBBackendPool) {
	if err := r.ciliumCli.CreateLBBackendPool(ctx, r.k8sNamespace, bp, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			fatalf("cannot create LB BackendPool (%s): %s", r.testName, err)
		}
	}
	RegisterMaybeCleanupAfterTest(func() error {
		return r.ciliumCli.DeleteLBBackendPool(ctx, bp.Namespace, bp.Name, metav1.DeleteOptions{})
	})
}

func (r *lbTestScenario) createLBService(ctx context.Context, svc *isovalentv1alpha1.LBService) {
	if err := r.ciliumCli.CreateLBService(ctx, r.k8sNamespace, svc, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			fatalf("cannot create LB Service (%s): %s", r.testName, err)
		}
	}
	RegisterMaybeCleanupAfterTest(func() error {
		return r.ciliumCli.DeleteLBService(ctx, svc.Namespace, svc.Name, metav1.DeleteOptions{})
	})
}

// createLBServerCertificate creates a server certificate that can be used to terminate TLS traffic on the Loadbalancer.
// In addition to creating the creating the cert & key, the corresponding K8s TLS Secret gets created.
//
// Note: Certificates need to be created before creating any FRR client that references the cert.
// Otherwise loading the cert into the corresponding docker container fails.
func (r *lbTestScenario) createLBServerCertificate(ctx context.Context, secretName string, hostName string) {
	key, cert, err := genSelfSignedX509(hostName)
	if err != nil {
		fatalf("failed to gen x509: %s", err)
	}

	sec := tlsSecret(r.k8sNamespace, secretName, key.Bytes(), cert.Bytes())
	if _, err := r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Create(ctx, sec, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			fatalf("failed to create secret (%s): %s", secretName, err)
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

	RegisterMaybeCleanupAfterTest(func() error {
		return r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Delete(ctx, secretName, metav1.DeleteOptions{})
	})
}

// createLBClientCertificate creates a client certificate that can be used to authenticate clients to the Loadbalancer.
// In addition to creating the creating the cert & key, the corresponding K8s TLS Secret gets created.
//
// Note: Certificates need to be created before creating any FRR client that references the cert.
// Otherwise loading the cert into the corresponding docker container fails.
func (r *lbTestScenario) createLBClientCertificate(ctx context.Context, caName, hostName string) {
	// Generate CA cert and key
	caPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatalf("failed to generate CA priv key: %s", err)
	}

	caTemplate, err := genTemplate(caName, x509.KeyUsageDigitalSignature|x509.KeyUsageCRLSign|x509.KeyUsageCertSign, nil)
	if err != nil {
		fatalf("failed to gen CA template: %s", err)
	}

	caCertDERBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		fatalf("failed to create CA cert: %s", err)
	}

	_, caCert, err := encodePEM(caCertDERBytes, caPriv)
	if err != nil {
		fatalf("failed to encode CA PEM: %s", err)
	}

	caSec := caSecret(r.k8sNamespace, r.testName+"-client-ca", caCert.Bytes())
	if _, err := r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Create(ctx, caSec, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			fatalf("failed to create CA secret (%s): %s", r.testName, err)
		}
	}

	RegisterMaybeCleanupAfterTest(func() error {
		return r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Delete(ctx, caSec.Name, metav1.DeleteOptions{})
	})

	clientPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatalf("failed to generate priv key: %s", err)
	}

	// Generate client cert and key signed with CA cert
	clientTemplate, err := genTemplate(hostName, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if err != nil {
		fatalf("failed to gen client template: %s", err)
	}

	clientCertDERBytes, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientPriv.PublicKey, caPriv)
	if err != nil {
		fatalf("failed to create client cert: %s", err)
	}

	clientKey, clientCert, err := encodePEM(clientCertDERBytes, clientPriv)
	if err != nil {
		fatalf("failed to encode client PEM: %s", err)
	}

	// Store client certificates for later use
	certBytes := clientCert.Bytes()
	keyBytes := clientKey.Bytes()
	r.clientCertificates[hostName] = &tlsCertificate{
		cert:       certBytes,
		key:        keyBytes,
		certBase64: base64.StdEncoding.EncodeToString(certBytes),
		keyBase64:  base64.StdEncoding.EncodeToString(keyBytes),
	}
}

// createBackendServerCertificate creates a server certificate that can be used to terminate TLS traffic on a backend application.
//
// Note: Certificates need to be created before creating any backend application or FRR client that references the cert.
// Otherwise loading the cert/key into the corresponding docker container fails.
func (r *lbTestScenario) createBackendServerCertificate(_ context.Context, hostName string) {
	key, cert, err := genSelfSignedX509(hostName)
	if err != nil {
		fatalf("failed to gen x509: %s", err)
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

type basicAuthCredential struct {
	username string
	password string
}

func (r *lbTestScenario) createBasicAuthSecret(ctx context.Context, creds []basicAuthCredential) string {
	sec := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: r.testName + "-basic-auth",
		},
		StringData: map[string]string{},
	}

	for _, c := range creds {
		sec.StringData[c.username] = c.password
	}

	if _, err := r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Create(ctx, &sec, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			fatalf("failed to create secret (%s): %s", r.testName, err)
		}
	}
	RegisterMaybeCleanupAfterTest(func() error {
		return r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Delete(ctx, sec.Name, metav1.DeleteOptions{})
	})

	return sec.Name
}

func (r *lbTestScenario) createJWKSSecret(ctx context.Context, providerName string, jwks []byte) string {
	sec := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: r.testName + "-" + providerName + "-jwt-auth",
		},
		StringData: map[string]string{
			isovalentv1alpha1.LBServiceJWKSSecretKey: string(jwks),
		},
	}

	if _, err := r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Create(ctx, &sec, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			fatalf("failed to create secret (%s): %s", r.testName, err)
		}
	}
	RegisterMaybeCleanupAfterTest(func() error {
		return r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Delete(ctx, sec.Name, metav1.DeleteOptions{})
	})

	return sec.Name
}
