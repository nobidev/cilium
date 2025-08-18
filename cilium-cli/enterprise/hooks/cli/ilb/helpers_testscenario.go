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
	"encoding/json"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/models"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalentv1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	metaslimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8s "github.com/cilium/cilium/pkg/k8s/slim/k8s/clientset"
)

const (
	// use different ASN for Cilium & FRR -> eBGP
	ciliumASN = 64512
	frrASN    = 64513
)

type lbTestScenario struct {
	t T

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

func newLBTestScenario(t T, testName string, ciliumCli *ciliumCli, k8sCli *k8s.Clientset, dockerCli *dockerCli) *lbTestScenario {
	k8sNamespace := fmt.Sprintf("ilb-test-%s", testName)

	scenario := &lbTestScenario{
		t:                   t,
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

	if _, err := scenario.k8sCli.CoreV1().Namespaces().Create(t.Context(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: k8sNamespace}}, metav1.CreateOptions{}); err != nil {
		t.Failedf("failed to create test namespace %q: %s", k8sNamespace, err)
	}

	t.RegisterCleanup(func(ctx context.Context) error {
		if _, err := k8sCli.CoreV1().Namespaces().Get(ctx, k8sNamespace, metav1.GetOptions{}); errors.IsNotFound(err) {
			return nil
		}

		err := k8sCli.CoreV1().Namespaces().Delete(ctx, k8sNamespace,
			metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)})
		if err != nil {
			return fmt.Errorf("failed to delete namespace (%s): %w", k8sNamespace, err)
		}
		t.Log("Waiting for namespace %s to be deleted...", k8sNamespace)
		eventually(t, func() error {
			if _, err := k8sCli.CoreV1().Namespaces().Get(ctx, k8sNamespace, metav1.GetOptions{}); errors.IsNotFound(err) {
				return nil
			}
			return fmt.Errorf("namespace (%s) still exists", k8sNamespace)
		}, longTimeout, pollInterval)
		return nil
	})

	return scenario
}

func (r *lbTestScenario) waitForFullVIPConnectivity(vipName string) string {
	ip, err := r.ciliumCli.WaitForLBVIP(r.t.Context(), r.k8sNamespace, vipName)
	if err != nil {
		r.t.Failedf("failed to wait for VIP (%s): %s", vipName, err)
	}

	for _, c := range r.frrClients {
		eventually(r.t, func() error {
			return c.EnsureRoute(r.t.Context(), ip+"/32")
		}, longTimeout, pollInterval)
	}

	return ip
}

func (r *lbTestScenario) waitForAllT2EndpointsActive(testName string, vipIP string, vipPort uint16, t1NodeList *corev1.NodeList, t2NodeList *corev1.NodeList) {
	eventually(r.t, func() error {
		return r.allT2EndpointsActive(testName, vipIP, vipPort, t1NodeList, t2NodeList)
	}, longTimeout, pollInterval)
}

// allT2EndpointsActive checks that all T2 endpoints are active on all T1 nodes
func (r *lbTestScenario) allT2EndpointsActive(testName string, vipIP string, vipPort uint16, t1NodeList *corev1.NodeList, t2NodeList *corev1.NodeList) error {
	podList, err := r.k8sCli.CoreV1().Pods(ciliumNamespace).List(r.t.Context(), metav1.ListOptions{
		LabelSelector: ciliumAgentPodLabelSelector,
	})
	if err != nil {
		return fmt.Errorf("failed to list cilium agent pods: %w", err)
	}

	for _, t1 := range t1NodeList.Items {
		podName := ciliumAgentPodNameForNode(podList, t1.Name)
		if podName == "" {
			return fmt.Errorf("failed to get cilium agent pod for node %s: %w", t1.Name, err)
		}

		stdout, _, err := execIntoPod(r.t, r.k8sCli, ciliumNamespace, podName, "cilium-agent", []string{"cilium-dbg", "service", "list", "-o", "json"})
		if err != nil {
			return fmt.Errorf("failed to list service info on node %s: %w", t1.Name, err)
		}

		services := make([]*models.Service, 0)

		if err := json.Unmarshal(stdout.Bytes(), &services); err != nil {
			return fmt.Errorf("failed to unmarshal service status from %s: %w", podName, err)
		}

		for _, s := range services {
			if s.Status != nil && s.Status.Realized != nil && s.Status.Realized.FrontendAddress != nil && s.Status.Realized.Flags != nil &&
				s.Status.Realized.Flags.Type == "LoadBalancer" &&
				s.Status.Realized.Flags.Name == "lbfe-"+testName &&
				s.Status.Realized.FrontendAddress.IP == vipIP &&
				s.Status.Realized.FrontendAddress.Port == vipPort {

				allT2Active := true
				for _, backendAddress := range s.Status.Realized.BackendAddresses {
					if backendAddress.State != "active" {
						allT2Active = false
						break
					}
				}

				if len(s.Status.Realized.BackendAddresses) != len(t2NodeList.Items) || !allT2Active {
					return fmt.Errorf("not all t2 endpointsare active yet")
				}

				break
			}
		}
	}

	return nil
}

func ciliumAgentPodNameForNode(podList *corev1.PodList, nodeName string) string {
	for _, p := range podList.Items {
		if p.Spec.NodeName == nodeName {
			return p.Name
		}
	}

	return ""
}

func (r *lbTestScenario) addCoreDNS() *coreDNSContainer {
	if r.coreDNSContainer != nil {
		return r.coreDNSContainer
	}

	name := fmt.Sprintf("%s-coredns", r.testName)

	// We must create an initial file before starting the container. Otherwise,
	// CoreDNS uses on-memory default configuration and we cannot update it later.
	preStart := func(c *dockerCli, id string) error {
		return c.copyToContainer(r.t.Context(), id, []byte(". {}"), "Corefile", "/tmp")
	}

	// Override the default port to avoid colliding with the rest of the system
	id, ip, err := r.dockerCli.createContainer(r.t.Context(), name, FlagCoreDNSImage, nil, containerNetwork, false, []string{"-conf", "/tmp/Corefile", "-dns.port", "10053"}, preStart)
	if err != nil {
		r.t.Failedf("cannot create CoreDNS container: %s", err)
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

	r.t.RegisterCleanup(func(ctx context.Context) error { return r.dockerCli.deleteContainer(ctx, id) })

	return container
}

func (r *lbTestScenario) addNginx() *nginxContainer {
	if r.nginxContainer != nil {
		return r.nginxContainer
	}

	name := fmt.Sprintf("%s-nginx", r.testName)

	id, ip, err := r.dockerCli.createContainer(r.t.Context(), name, FlagNginxImage, nil, containerNetwork, false, nil, nil)
	if err != nil {
		r.t.Failedf("cannot create Nginx container: %s", err)
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

	r.t.RegisterCleanup(func(ctx context.Context) error { return r.dockerCli.deleteContainer(ctx, id) })

	return container
}

func (r *lbTestScenario) addBackendApplications(numberOfBackends int, config backendApplicationConfig) []*hcAppContainer {
	containers := []*hcAppContainer{}
	startIndex := len(r.backendApps)

	if config.listenPort == 0 {
		config.listenPort = 8080
	}

	if config.image == "" {
		config.image = FlagAppImage
	}

	for i := startIndex; i < startIndex+numberOfBackends; i++ {
		appName := fmt.Sprintf("%s-app-%d", r.testName, i)
		envVars := r.getBackendApplicationEnvVars(appName, config)

		id, ip, err := r.dockerCli.createContainer(r.t.Context(), appName, config.image, envVars, containerNetwork, false, nil, nil)
		if err != nil {
			r.t.Failedf("cannot create app container (%s): %s", appName, err)
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

		r.t.RegisterCleanup(func(ctx context.Context) error { return r.dockerCli.deleteContainer(ctx, id) })
	}

	return containers
}

func (r *lbTestScenario) desiredBackendK8sDeployment(t T, name string, replicas int32, config backendApplicationConfig) *appsv1.Deployment {
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
			t.Failedf("failed to gen x509: %s", err)
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

func (r *lbTestScenario) desiredBackendK8sService(name string, port int32, targetPort int32) *corev1.Service {
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
					Protocol:   corev1.ProtocolTCP,
					Port:       port,
					TargetPort: intstr.FromInt32(targetPort),
				},
			},
		},
	}
}

func (r *lbTestScenario) AddAndWaitForK8sBackendApplications(name string, replicas int32, backendTLSCertHostname string) *corev1.PodList {
	var deployment *appsv1.Deployment

	if len(backendTLSCertHostname) > 0 {
		deployment = r.desiredBackendK8sDeployment(r.t, name, replicas, backendApplicationConfig{
			tlsCertHostname: backendTLSCertHostname,
		})
	} else {
		deployment = r.desiredBackendK8sDeployment(r.t, name, replicas, backendApplicationConfig{
			h2cEnabled: true,
		})
	}

	if _, err := r.k8sCli.AppsV1().Deployments(r.k8sNamespace).Create(r.t.Context(), deployment, metav1.CreateOptions{}); err != nil {
		r.t.Failedf("failed to create deployment (%s): %s", deployment.Name, err)
	}
	r.t.RegisterCleanup(func(ctx context.Context) error {
		return r.k8sCli.AppsV1().Deployments(r.k8sNamespace).Delete(ctx, deployment.Name, metav1.DeleteOptions{})
	})

	service := r.desiredBackendK8sService(name, 8080, 8080)
	if _, err := r.k8sCli.CoreV1().Services(r.k8sNamespace).Create(r.t.Context(), service, metav1.CreateOptions{}); err != nil {
		r.t.Failedf("failed to create service (%s): %s", service.Name, err)
	}
	r.t.RegisterCleanup(func(ctx context.Context) error {
		return r.k8sCli.CoreV1().Services(r.k8sNamespace).Delete(ctx, service.Name, metav1.DeleteOptions{})
	})

	watch, err := r.k8sCli.AppsV1().Deployments(r.k8sNamespace).Watch(r.t.Context(), metav1.ListOptions{
		LabelSelector: "app=" + name,
	})
	if err != nil {
		r.t.Failedf("failed to watch deployment (%s) in namespace (%s): %s", name, r.k8sNamespace, err)
	}
	defer watch.Stop()

	timeout := time.After(longTimeout)

	for {
		var completed bool
		select {
		case ev := <-watch.ResultChan():
			deploy, ok := ev.Object.(*appsv1.Deployment)
			if !ok {
				r.t.Failedf("unexpected object type: %T", ev.Object)
			}
			if deploy.Name != name {
				continue
			}
			if deploy.Status.ReadyReplicas != replicas {
				continue
			}
			completed = true
		case <-timeout:
			r.t.Failedf("timed out waiting for deployment (%s) in namespace (%s)", name, r.k8sNamespace)
		}
		if completed {
			break
		}
	}

	pods, err := r.k8sCli.CoreV1().Pods(r.k8sNamespace).List(r.t.Context(), metav1.ListOptions{
		LabelSelector: "app=" + name,
	})
	if err != nil {
		r.t.Failedf("failed to list pods (%s) in namespace (%s): %s", name, r.k8sNamespace, err)
	}

	return pods
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
			r.t.Failedf("backend certificate with hostname %q not found", config.tlsCertHostname)
		}

		env = append(env, "TLS_ENABLED=true")
		env = append(env, "TLS_KEY_BASE64="+cert.keyBase64)
		env = append(env, "TLS_CERT_BASE64="+cert.certBase64)
	}

	if config.listenPort != 0 {
		env = append(env, fmt.Sprintf("LISTEN_ADDRESS=:%d", config.listenPort))
	}

	// add additional env vars
	for k, v := range config.envVars {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}

	return env
}

func (r *lbTestScenario) addFRRClients(numberOfClients int, config frrClientConfig) []*frrContainer {
	containers := []*frrContainer{}
	startIndex := len(r.frrClients)

	// Lazily create the per-scenario BGP-related resources here. Calling
	// addFRRClients multiple times will not create multiple resource. The
	// resources created in the first call will be reused.
	r.createBGPPeerConfig()
	r.createBFDProfile()

	for i := startIndex; i < startIndex+numberOfClients; i++ {
		clientName := fmt.Sprintf("%s-client-%d", r.testName, i)
		env := []string{
			fmt.Sprintf("LOCAL_ASN=%d", frrASN),
			fmt.Sprintf("REMOTE_ASN=%d", ciliumASN),
			"NEIGHBORS=" + getBGPNeighborString(r.t, r.k8sCli),
		}

		id, ip, err := r.dockerCli.createContainer(r.t.Context(), clientName, FlagClientImage, env, containerNetwork, true, nil, nil)
		if err != nil {
			r.t.Failedf("cannot create frr client container (%s): %s", clientName, err)
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

		r.t.RegisterCleanup(func(ctx context.Context) error { return r.dockerCli.deleteContainer(ctx, id) })

		for _, h := range config.trustedCertsHostnames {
			sc, serverCertFound := r.serverCertificates[h]
			if !serverCertFound {
				bc, backendCertFound := r.backendCertificates[h]
				if !backendCertFound {
					r.t.Failedf("certificate for hostname %q doesn't exist", h)
				}
				sc = bc
			}

			if err := container.Copy(r.t.Context(), sc.cert, h+".crt", "/tmp"); err != nil {
				r.t.Failedf("failed to copy cert to client container: %s", err)
			}
		}

		for hostName, cert := range r.clientCertificates {
			if err := container.Copy(r.t.Context(), cert.cert, hostName+".crt", "/tmp"); err != nil {
				r.t.Failedf("failed to copy cert to client container: %s", err)
			}
			if err := container.Copy(r.t.Context(), cert.key, hostName+".key", "/tmp"); err != nil {
				r.t.Failedf("failed to copy key to client container: %s", err)
			}
		}

		// Make BGP peering with T1 nodes
		if err := r.doBGPPeeringForClient(r.t.Context(), clientName, ip); err != nil {
			r.t.Failedf("failed to BGP peer (%s): %s", clientName, err)
		}
		r.t.RegisterCleanup(func(ctx context.Context) error { return r.undoBGPPeeringForClient(ctx, ip) })
	}

	return containers
}

func (r *lbTestScenario) createBGPPeerConfig() {
	obj := &isovalentv1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: r.testName,
		},
		Spec: isovalentv1.IsovalentBGPPeerConfigSpec{
			CiliumBGPPeerConfigSpec: ciliumv2.CiliumBGPPeerConfigSpec{
				Families: []ciliumv2.CiliumBGPFamilyWithAdverts{
					{
						CiliumBGPFamily: ciliumv2.CiliumBGPFamily{
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
				Timers: &ciliumv2.CiliumBGPTimers{
					ConnectRetryTimeSeconds: ptr.To(int32(1)),
				},
			},
			BFDProfileRef: ptr.To(r.testName),
		},
	}
	if _, err := r.ciliumCli.IsovalentV1().IsovalentBGPPeerConfigs().Create(r.t.Context(), obj, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			r.t.Failedf("failed to create Peer config (%s): %s", obj.Name, err)
		}
	}
	r.t.RegisterCleanup(func(ctx context.Context) error {
		return r.ciliumCli.IsovalentV1().IsovalentBGPPeerConfigs().Delete(ctx, obj.Name, metav1.DeleteOptions{})
	})
}

func (r *lbTestScenario) createBFDProfile() {
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
	if _, err := r.ciliumCli.IsovalentV1alpha1().IsovalentBFDProfiles().Create(r.t.Context(), obj, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			r.t.Failedf("failed to create BFD profile (%s): %s", obj.Name, err)
		}
	}
	r.t.RegisterCleanup(func(ctx context.Context) error {
		return r.ciliumCli.IsovalentV1alpha1().IsovalentBFDProfiles().Delete(ctx, obj.Name, metav1.DeleteOptions{})
	})
}

func (r *lbTestScenario) createBGPAdvertisement(ctx context.Context, vipName string) {
	// BGP Advertisement has a one-to-one mapping with the VIP
	obj := &isovalentv1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: vipName,
			// This label is referenced in the BGPPeerConfig
			Labels: map[string]string{
				"scenario": r.testName,
			},
		},
		Spec: isovalentv1.IsovalentBGPAdvertisementSpec{
			Advertisements: []isovalentv1.BGPAdvertisement{
				{
					AdvertisementType: isovalentv1.BGPServiceAdvert,
					Service: &isovalentv1.BGPServiceOptions{
						Addresses: []ciliumv2.BGPServiceAddressType{
							ciliumv2.BGPLoadBalancerIPAddr,
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
	if _, err := r.ciliumCli.IsovalentV1().IsovalentBGPAdvertisements().Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			r.t.Failedf("failed to create BGP advertisement (%s): %s", obj.Name, err)
		}
	}
	r.t.RegisterCleanup(func(ctx context.Context) error {
		return r.ciliumCli.IsovalentV1().IsovalentBGPAdvertisements().Delete(ctx, obj.Name, metav1.DeleteOptions{})
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
		cc, err := r.ciliumCli.IsovalentV1().IsovalentBGPClusterConfigs().Get(ctx, globalBGPClusterConfigName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get BGP cluster config (%s): %w", globalBGPClusterConfigName, err)
		}

		cc.Spec.BGPInstances[0].Peers = append(cc.Spec.BGPInstances[0].Peers,
			isovalentv1.IsovalentBGPPeer{
				Name:        "peer-" + clientIP,
				PeerAddress: &clientIP,
				PeerASN:     ptr.To[int64](frrASN),
				PeerConfigRef: &isovalentv1.PeerConfigReference{
					Name: r.testName,
				},
			})

		if _, err := r.ciliumCli.IsovalentV1().IsovalentBGPClusterConfigs().Update(ctx, cc, metav1.UpdateOptions{}); err != nil {
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
		cc, err := r.ciliumCli.IsovalentV1().IsovalentBGPClusterConfigs().Get(ctx, globalBGPClusterConfigName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get BGP cluster config (%s): %w", globalBGPClusterConfigName, err)
		}

		peers := cc.Spec.BGPInstances[0].Peers

		updatedPeers := []isovalentv1.IsovalentBGPPeer{}
		for _, peer := range peers {
			if *peer.PeerAddress != clientIP {
				updatedPeers = append(updatedPeers, peer)
			}
		}

		cc.Spec.BGPInstances[0].Peers = updatedPeers
		if _, err := r.ciliumCli.IsovalentV1().IsovalentBGPClusterConfigs().Update(ctx, cc, metav1.UpdateOptions{}); err != nil {
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
func (r *lbTestScenario) createLBVIP(vip *isovalentv1alpha1.LBVIP) {
	if err := r.ciliumCli.CreateLBVIP(r.t.Context(), r.k8sNamespace, vip, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			r.t.Failedf("cannot create LB VIP (%s): %s", r.testName, err)
		}
	}
	r.t.RegisterCleanup(func(ctx context.Context) error {
		return r.ciliumCli.DeleteLBVIP(ctx, r.k8sNamespace, vip.Name, metav1.DeleteOptions{})
	})

	// Create BGPAdvertisement corresponding to the VIP
	r.createBGPAdvertisement(r.t.Context(), vip.Name)
}

func (r *lbTestScenario) createLBBackendPool(bp *isovalentv1alpha1.LBBackendPool) {
	if err := r.ciliumCli.CreateLBBackendPool(r.t.Context(), r.k8sNamespace, bp, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			r.t.Failedf("cannot create LB BackendPool (%s) in namespace (%s): %s", bp.Name, r.k8sNamespace, err)
		}
	}

	r.t.RegisterCleanup(func(ctx context.Context) error {
		return r.ciliumCli.DeleteLBBackendPool(ctx, r.k8sNamespace, bp.Name, metav1.DeleteOptions{})
	})
}

func (r *lbTestScenario) createLBService(svc *isovalentv1alpha1.LBService) {
	if err := r.ciliumCli.CreateLBService(r.t.Context(), r.k8sNamespace, svc, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			r.t.Failedf("cannot create LB Service (%s) in namespace (%s): %s", svc.Name, r.k8sNamespace, err)
		}
	}
	r.t.RegisterCleanup(func(ctx context.Context) error {
		return r.ciliumCli.DeleteLBService(ctx, r.k8sNamespace, svc.Name, metav1.DeleteOptions{})
	})
}

func (r *lbTestScenario) createLBDeployment(depl *isovalentv1alpha1.LBDeployment) {
	if err := r.ciliumCli.CreateLBDeployment(r.t.Context(), r.k8sNamespace, depl, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			r.t.Failedf("cannot create LB Deployment (%s): %s", r.testName, err)
		}
	}
	r.t.RegisterCleanup(func(ctx context.Context) error {
		return r.ciliumCli.DeleteLBDeployment(ctx, r.k8sNamespace, depl.Name, metav1.DeleteOptions{})
	})
}

// createLBServerCertificate creates a server certificate that can be used to terminate TLS traffic on the Loadbalancer.
// In addition to creating the creating the cert & key, the corresponding K8s TLS Secret gets created.
//
// Note: Certificates need to be created before creating any FRR client that references the cert.
// Otherwise loading the cert into the corresponding docker container fails.
func (r *lbTestScenario) createLBServerCertificate(secretName string, hostName string) {
	key, cert, err := genSelfSignedX509(hostName)
	if err != nil {
		r.t.Failedf("failed to gen x509: %s", err)
	}

	sec := tlsSecret(r.k8sNamespace, secretName, key.Bytes(), cert.Bytes())
	if _, err := r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Create(r.t.Context(), sec, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			r.t.Failedf("failed to create secret (%s): %s", secretName, err)
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

	r.t.RegisterCleanup(func(ctx context.Context) error {
		return r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Delete(ctx, secretName, metav1.DeleteOptions{})
	})
}

// createLBClientCertificate creates a client certificate that can be used to authenticate clients to the Loadbalancer.
// In addition to creating the creating the cert & key, the corresponding K8s TLS Secret gets created.
//
// Note: Certificates need to be created before creating any FRR client that references the cert.
// Otherwise loading the cert into the corresponding docker container fails.
func (r *lbTestScenario) createLBClientCertificate(caName, hostName string, opts ...certTemplateOpts) {
	// Generate CA cert and key
	caPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		r.t.Failedf("failed to generate CA priv key: %s", err)
	}

	caTemplate, err := genTemplate(x509.KeyUsageDigitalSignature|x509.KeyUsageCRLSign|x509.KeyUsageCertSign, nil, withCertificateSANDNSNames(caName))
	if err != nil {
		r.t.Failedf("failed to gen CA template: %s", err)
	}

	caCertDERBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		r.t.Failedf("failed to create CA cert: %s", err)
	}

	_, caCert, err := encodePEM(caCertDERBytes, caPriv)
	if err != nil {
		r.t.Failedf("failed to encode CA PEM: %s", err)
	}

	caSec := caSecret(r.k8sNamespace, r.testName+"-client-ca", caCert.Bytes())
	if _, err := r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Create(r.t.Context(), caSec, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			r.t.Failedf("failed to create CA secret (%s): %s", r.testName, err)
		}
	}

	r.t.RegisterCleanup(func(ctx context.Context) error {
		return r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Delete(ctx, caSec.Name, metav1.DeleteOptions{})
	})

	clientPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		r.t.Failedf("failed to generate priv key: %s", err)
	}

	templateOpts := []certTemplateOpts{}
	templateOpts = append(templateOpts, opts...)

	if len(opts) == 0 {
		templateOpts = append(templateOpts, withCertificateSANDNSNames(hostName))
	}

	// Generate client cert and key signed with CA cert
	clientTemplate, err := genTemplate(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		templateOpts...,
	)
	if err != nil {
		r.t.Failedf("failed to gen client template: %s", err)
	}

	clientCertDERBytes, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientPriv.PublicKey, caPriv)
	if err != nil {
		r.t.Failedf("failed to create client cert: %s", err)
	}

	clientKey, clientCert, err := encodePEM(clientCertDERBytes, clientPriv)
	if err != nil {
		r.t.Failedf("failed to encode client PEM: %s", err)
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
func (r *lbTestScenario) createBackendServerCertificate(hostName string) {
	key, cert, err := genSelfSignedX509(hostName)
	if err != nil {
		r.t.Failedf("failed to gen x509: %s", err)
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

func (r *lbTestScenario) createBasicAuthSecret(creds []basicAuthCredential) string {
	sec := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: r.testName + "-basic-auth",
		},
		StringData: map[string]string{},
	}

	for _, c := range creds {
		sec.StringData[c.username] = c.password
	}

	if _, err := r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Create(r.t.Context(), &sec, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			r.t.Failedf("failed to create secret (%s): %s", r.testName, err)
		}
	}
	r.t.RegisterCleanup(func(ctx context.Context) error {
		return r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Delete(ctx, sec.Name, metav1.DeleteOptions{})
	})

	return sec.Name
}

func (r *lbTestScenario) createJWKSSecret(providerName string, jwks []byte) string {
	sec := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: r.testName + "-" + providerName + "-jwt-auth",
		},
		StringData: map[string]string{
			isovalentv1alpha1.LBServiceJWKSSecretKey: string(jwks),
		},
	}

	if _, err := r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Create(r.t.Context(), &sec, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			r.t.Failedf("failed to create secret (%s): %s", r.testName, err)
		}
	}
	r.t.RegisterCleanup(func(ctx context.Context) error {
		return r.k8sCli.CoreV1().Secrets(r.k8sNamespace).Delete(ctx, sec.Name, metav1.DeleteOptions{})
	})

	return sec.Name
}
