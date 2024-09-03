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
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	docker_client "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"github.com/cilium/cilium/pkg/inctimer"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	cilium_clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	k8s "github.com/cilium/cilium/pkg/k8s/slim/k8s/clientset"
	"github.com/cilium/cilium/pkg/safeio"
)

const (
	shortTimeout     = 30 * time.Second
	longTimeout      = 60 * time.Second
	pollInterval     = 1 * time.Second
	longPollInterval = 5 * time.Second

	bgpPolicyName = "ilb-test"
)

type ciliumCli struct {
	*cilium_clientset.Clientset
}

func newCiliumAndK8sCli() (*ciliumCli, *k8s.Clientset, error) {
	kubeConfigPath := filepath.Join(homedir.HomeDir(), ".kube", "config")

	restConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		panic(err)
	}

	httpClient, err := rest.HTTPClientFor(restConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create k8s REST client: %w", err)
	}

	cli, err := cilium_clientset.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create cilium k8s client: %w", err)
	}

	k8s := k8s.NewForConfigOrDie(restConfig)

	return &ciliumCli{cli}, k8s, nil
}

func (c *ciliumCli) CreateLBVIP(ctx context.Context, namespace string, obj *isovalentv1alpha1.LBVIP, opts metav1.CreateOptions) error {
	_, err := c.IsovalentV1alpha1().LBVIPs(namespace).Create(ctx, obj, opts)
	return err
}

func (c *ciliumCli) DeleteLBVIP(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.IsovalentV1alpha1().LBVIPs(namespace).Delete(ctx, name, opts)
}

func (c *ciliumCli) CreateLBService(ctx context.Context, namespace string, obj *isovalentv1alpha1.LBService, opts metav1.CreateOptions) error {
	_, err := c.IsovalentV1alpha1().LBServices(namespace).Create(ctx, obj, opts)
	return err
}

func (c *ciliumCli) DeleteLBService(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.IsovalentV1alpha1().LBServices(namespace).Delete(ctx, name, opts)
}

func (c *ciliumCli) GetLBService(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*isovalentv1alpha1.LBService, error) {
	return c.IsovalentV1alpha1().LBServices(namespace).Get(ctx, name, opts)
}

func (c *ciliumCli) CreateLBBackend(ctx context.Context, namespace string, obj *isovalentv1alpha1.LBBackendPool, opts metav1.CreateOptions) error {
	_, err := c.IsovalentV1alpha1().LBBackendPools(namespace).Create(ctx, obj, opts)
	return err
}

func (c *ciliumCli) DeleteLBBackend(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.IsovalentV1alpha1().LBBackendPools(namespace).Delete(ctx, name, opts)
}

func (c *ciliumCli) CreateLBIPPool(ctx context.Context, obj *ciliumv2alpha1.CiliumLoadBalancerIPPool, opts metav1.CreateOptions) error {
	_, err := c.CiliumV2alpha1().CiliumLoadBalancerIPPools().Create(ctx, obj, opts)
	return err
}

func (c *ciliumCli) DeleteLBIPPool(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.CiliumV2alpha1().CiliumLoadBalancerIPPools().Delete(ctx, name, opts)
}

func (c *ciliumCli) WaitForLBVIP(ctx context.Context, namespace, name string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, shortTimeout)
	defer cancel()

	for {
		obj, err := c.GetLBService(ctx, namespace, name, metav1.GetOptions{})
		if err != nil {
			return "", err
		}

		if ip := obj.Status.Addresses.IPv4; ip != nil {
			return *ip, nil
		}

		select {
		case <-inctimer.After(pollInterval):
		case <-ctx.Done():
			return "",
				fmt.Errorf("timeout reached waiting for LB Service %s to get VIP assigned (last error: %w)",
					name, err)
		}
	}
}

func (c *ciliumCli) ensureBGPPeeringPolicyAndBFD(ctx context.Context) error {
	pol := bgpPeeringPolicy(bgpPolicyName)
	if _, err := c.CiliumV2alpha1().CiliumBGPPeeringPolicies().Create(ctx, pol, metav1.CreateOptions{}); err != nil {
		if !k8s_errors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create BGP peering policy (%s): %w", bgpPolicyName, err)
		}
	}

	bfd := bfdProfile(bgpPolicyName)
	if _, err := c.IsovalentV1alpha1().IsovalentBFDProfiles().Create(ctx, bfd, metav1.CreateOptions{}); err != nil {
		if !k8s_errors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create BFD profile (%s): %w", bgpPolicyName, err)
		}
	}

	return nil
}

func (c *ciliumCli) deleteBGPPeeringPolicyAndBFD(ctx context.Context) error {
	if err := c.IsovalentV1alpha1().IsovalentBFDProfiles().Delete(ctx, bgpPolicyName, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("failed to delete BFD profile (%s): %w", bgpPolicyName, err)
	}

	if err := c.CiliumV2alpha1().CiliumBGPPeeringPolicies().Delete(ctx, bgpPolicyName, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("failed to delete BGP peering policy (%s): %w", bgpPolicyName, err)
	}

	return nil
}

func (c *ciliumCli) doBGPPeeringForClient(ctx context.Context, clientIP string) error {
	pol, err := c.CiliumV2alpha1().CiliumBGPPeeringPolicies().Get(ctx, bgpPolicyName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get BGP peering policy (%s): %w", bgpPolicyName, err)
	}

	name := bgpPolicyName
	pol.Spec.VirtualRouters[0].Neighbors = append(pol.Spec.VirtualRouters[0].Neighbors,
		ciliumv2alpha1.CiliumBGPNeighbor{
			PeerAddress:   clientIP + "/32",
			PeerASN:       64512,
			BFDProfileRef: &name,
		})

	if _, err := c.CiliumV2alpha1().CiliumBGPPeeringPolicies().Update(ctx, pol, metav1.UpdateOptions{}); err != nil {
		// TODO(brb) handle conflict+retry (once we start running tests in parallel)
		return fmt.Errorf("failed to update BGP peering policy (%s): %w", bgpPolicyName, err)
	}

	return nil
}

func (c *ciliumCli) undoBGPPeeringForClient(ctx context.Context, clientIP string) error {
	pol, err := c.CiliumV2alpha1().CiliumBGPPeeringPolicies().Get(ctx, bgpPolicyName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get BGP peering policy (%s): %w", bgpPolicyName, err)
	}

	neighbors := pol.Spec.VirtualRouters[0].Neighbors

	updatedNeighbors := []ciliumv2alpha1.CiliumBGPNeighbor{}
	for _, neigh := range neighbors {
		if neigh.PeerAddress != clientIP+"/32" {
			updatedNeighbors = append(updatedNeighbors, neigh)
		}
	}

	pol.Spec.VirtualRouters[0].Neighbors = updatedNeighbors
	if _, err := c.CiliumV2alpha1().CiliumBGPPeeringPolicies().Update(ctx, pol, metav1.UpdateOptions{}); err != nil {
		// TODO(brb) handle conflict+retry (once we start running tests in parallel)
		return fmt.Errorf("failed to update BGP peering policy (%s): %w", bgpPolicyName, err)
	}

	return nil
}

func (c *ciliumCli) ensureLBIPPool(ctx context.Context, obj *ciliumv2alpha1.CiliumLoadBalancerIPPool) error {
	if err := c.CreateLBIPPool(ctx, obj, metav1.CreateOptions{}); err != nil {
		if !k8s_errors.IsAlreadyExists(err) {
			return err
		}
	}
	return nil
}

type dockerCli struct {
	*docker_client.Client
}

func newDockerCli() (*dockerCli, error) {
	cli, err := docker_client.NewClientWithOpts(docker_client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("failed to open Docker client: %w", err)
	}

	return &dockerCli{cli}, nil
}

func (c *dockerCli) GetContainerIP(ctx context.Context, containerName string) (string, error) {
	obj, err := c.ContainerInspect(ctx, containerName)
	if err != nil {
		return "", err
	}

	for _, network := range obj.NetworkSettings.Networks {
		return network.IPAddress, nil
	}

	return "", fmt.Errorf("no network found")
}

func (c *dockerCli) ContainerExec(ctx context.Context, name string, cmds []string) (string, string, error) {
	var stdout, stderr bytes.Buffer

	execConfig := container.ExecOptions{
		AttachStderr: true,
		AttachStdout: true,
		Cmd:          cmds,
	}

	execID, err := c.ContainerExecCreate(ctx, name, execConfig)
	if err != nil {
		return "", "", nil
	}

	resp, err := c.ContainerExecAttach(ctx, execID.ID, container.ExecAttachOptions{})
	if err != nil {
		return "", "", err
	}
	defer resp.Close()

	_, err = stdcopy.StdCopy(&stdout, &stderr, resp.Reader)
	if err != nil {
		return stdout.String(), stderr.String(), err
	}

	inspect, err := c.ContainerExecInspect(ctx, execID.ID)
	if err != nil {
		return stdout.String(), stderr.String(), err
	}

	if inspect.ExitCode != 0 {
		return stdout.String(), stderr.String(), fmt.Errorf("cmd failed: %d", inspect.ExitCode)
	}

	return stdout.String(), stderr.String(), err
}

func (c *dockerCli) clientExec(ctx context.Context, clientContainerName, cmd string) (string, string, error) {
	stdout, stderr, err := c.ContainerExec(ctx, clientContainerName,
		[]string{"bash", "-c", cmd},
	)

	return stdout, stderr, err
}

func (c *dockerCli) ensureImage(ctx context.Context, img string) error {
	reader, err := c.ImagePull(ctx, img, image.PullOptions{})
	if err != nil {
		return err
	}
	defer reader.Close()
	// wait until pulled
	if _, err := safeio.ReadAllLimit(reader, safeio.TB); err != nil {
		return err
	}

	return nil
}

func (c *dockerCli) createContainer(ctx context.Context, name, img string, env []string, networkName string, privileged bool) (string, string, error) {
	c.ContainerRemove(ctx, name, container.RemoveOptions{Force: true})

	resp, err := c.ContainerCreate(ctx,
		&container.Config{
			Image: img,
			Env:   env,
		},
		&container.HostConfig{
			Privileged: privileged,
		},
		&network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{
				networkName: {},
			},
		},
		nil,
		name,
	)
	if err != nil {
		return "", "", err
	}

	if err := c.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return "", "", err
	}

	clientIP, err := c.GetContainerIP(ctx, resp.ID)
	if err != nil {
		return "", "", err
	}

	return resp.ID, clientIP, nil
}

func (c *dockerCli) deleteContainer(ctx context.Context, name string) error {
	return c.ContainerRemove(ctx, name, container.RemoveOptions{Force: true})
}

func (c *dockerCli) waitForIPRoute(ctx context.Context, clientName, lbIP string) error {
	ctx, cancel := context.WithTimeout(ctx, shortTimeout)
	defer cancel()

	for {
		cmd := "ip route list | grep -qF " + lbIP
		stdout, stderr, err := c.clientExec(ctx, clientName, cmd)
		if err == nil {
			break
		}

		select {
		case <-inctimer.After(pollInterval):
		case <-ctx.Done():
			return fmt.Errorf("timeout reached waiting for IP route to LB VIP (stdout: %q, stderr: %q, err: %w",
				stdout, stderr, err)
		}
	}

	return nil
}

func (c *dockerCli) copyToContainer(ctx context.Context, containerID string, content []byte, dstFile, dstDir string) error {
	reader, err := createTAR(content, dstFile)
	if err != nil {
		return fmt.Errorf("failed to create tar for %s: %w", dstFile, err)
	}

	opts := container.CopyToContainerOptions{AllowOverwriteDirWithFile: true}
	return c.CopyToContainer(ctx, containerID, dstDir, reader, opts)
}

type hcState string

const (
	hcFail hcState = "fail"
	hcOK   hcState = "ok"
)

func (c *dockerCli) controlBackendHC(ctx context.Context, clientName, ip string, hc hcState) error {
	stdout, stderr, err := c.clientExec(ctx, clientName,
		fmt.Sprintf("curl --silent -X POST http://%s:8080/control/healthcheck/"+string(hc), ip))
	if err != nil {
		return fmt.Errorf("failed cmd (stdout: %q, stderr: %q): %w", stdout, stderr, err)
	}

	state := "false"
	if hc == hcOK {
		state = "true"
	}
	if strings.TrimSpace(stdout) != "healthcheck OK: "+state {
		return fmt.Errorf("expected different output, got %q", stdout)
	}

	return nil
}

func curlCmdVerbose(extra string) string {
	return "curl -w '%{local_ip}:%{local_port} -> %{remote_ip}:%{remote_port} = %{response_code}' --silent --fail --show-error " + extra
}

func curlCmd(extra string) string {
	return "curl --silent --fail --show-error " + extra
}

func genSelfSignedX509(host string) (*bytes.Buffer, *bytes.Buffer, error) {
	var key, cert bytes.Buffer

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate priv key: %w", err)
	}

	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment

	notBefore := time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate SN: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cert: %w", err)
	}

	if err := pem.Encode(&cert, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, nil, fmt.Errorf("failed to PEM encode cert: %w", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal pri key: %w", err)
	}

	if err := pem.Encode(&key, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, nil, fmt.Errorf("failed to PEM encode key: %w", err)
	}

	return &key, &cert, nil
}

func createTAR(content []byte, path string) (io.Reader, error) {
	var buf bytes.Buffer

	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{
		Name: filepath.Base(path),
		Mode: 0600,
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, fmt.Errorf("failed to write TAR hdr: %w", err)
	}
	if _, err := tw.Write(content); err != nil {
		return nil, fmt.Errorf("failed to write TAR: %w", err)
	}

	return bytes.NewReader(buf.Bytes()), nil
}
