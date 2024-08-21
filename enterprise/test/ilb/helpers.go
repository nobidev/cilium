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
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	docker_client "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"github.com/cilium/cilium/pkg/inctimer"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	cilium_clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
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

func newCiliumCli() (*ciliumCli, error) {
	kubeConfigPath := filepath.Join(homedir.HomeDir(), ".kube", "config")

	restConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		panic(err)
	}

	httpClient, err := rest.HTTPClientFor(restConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create k8s REST client: %w", err)
	}

	cli, err := cilium_clientset.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to create cilium k8s client: %w", err)
	}

	return &ciliumCli{cli}, nil
}

func (c *ciliumCli) CreateLBVIP(ctx context.Context, namespace string, obj *isovalentv1alpha1.LBVIP, opts metav1.CreateOptions) error {
	_, err := c.IsovalentV1alpha1().LBVIPs(namespace).Create(ctx, obj, opts)
	return err
}

func (c *ciliumCli) DeleteLBVIP(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.IsovalentV1alpha1().LBVIPs(namespace).Delete(ctx, name, opts)
}

func (c *ciliumCli) CreateLBFrontend(ctx context.Context, namespace string, obj *isovalentv1alpha1.LBFrontend, opts metav1.CreateOptions) error {
	_, err := c.IsovalentV1alpha1().LBFrontends(namespace).Create(ctx, obj, opts)
	return err
}

func (c *ciliumCli) DeleteLBFrontend(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error {
	return c.IsovalentV1alpha1().LBFrontends(namespace).Delete(ctx, name, opts)
}

func (c *ciliumCli) GetLBFrontend(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*isovalentv1alpha1.LBFrontend, error) {
	return c.IsovalentV1alpha1().LBFrontends(namespace).Get(ctx, name, opts)
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
		obj, err := c.GetLBFrontend(ctx, namespace, name, metav1.GetOptions{})
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
				fmt.Errorf("timeout reached waiting for LB Frontend %s to get VIP assigned (last error: %w)",
					name, err)
		}
	}
}

func (c *ciliumCli) doBGPPeeringForClient(ctx context.Context, clientIP string) error {
	pol := bgpPeeringPolicy(bgpPolicyName, clientIP)

	if _, err := c.CiliumV2alpha1().CiliumBGPPeeringPolicies().Create(ctx, pol, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create BGP peering policy (%s): %w", bgpPolicyName, err)
		} else {
			// Cilium's BGP does not allow us to create multiple peering policies targeting the same node.
			// Hence, append the client to the neighbor list of the existing policy.
			//
			// Also, no need to create BFD profile, as it should exist from previous tests.
			return c.appendBGPPeer(ctx, clientIP)
		}
	}

	bfd := bfdProfile(bgpPolicyName)

	if _, err := c.IsovalentV1alpha1().IsovalentBFDProfiles().Create(ctx, bfd, metav1.CreateOptions{}); err != nil {
		if !errors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create BFD profile (%s): %w", bgpPolicyName, err)
		}
	}

	return nil
}

func (c *ciliumCli) appendBGPPeer(ctx context.Context, clientIP string) error {
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

	// Only one neighbor, which is to-be deleted, exists, so we can entirely remove the policy.
	if len(neighbors) == 1 {
		if err := c.CiliumV2alpha1().CiliumBGPPeeringPolicies().Delete(ctx, bgpPolicyName, metav1.DeleteOptions{}); err != nil {
			return fmt.Errorf("failed to delete BGP peering policy (%s): %w", bgpPolicyName, err)
		}

		if err := c.IsovalentV1alpha1().IsovalentBFDProfiles().Delete(ctx, bgpPolicyName, metav1.DeleteOptions{}); err != nil {
			return fmt.Errorf("failed to delete BFD profile (%s): %w", bgpPolicyName, err)
		}

		return nil
	}

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
		if !errors.IsAlreadyExists(err) {
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
	if _, err := io.ReadAll(reader); err != nil {
		return err
	}

	return nil
}

func (c *dockerCli) createContainer(ctx context.Context, name, img string, env []string, networkName string, privileged bool) error {
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
		return err
	}

	if err := c.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return err
	}

	return nil
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

func yamlToObjects[T runtime.Object](input string, scheme *runtime.Scheme) (output []T, err error) {
	if input == "" {
		return nil, nil
	}

	yamls := strings.Split(input, "\n---")

	for _, yaml := range yamls {
		if strings.TrimSpace(yaml) == "" {
			continue
		}

		obj, kind, err := serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDeserializer().Decode([]byte(yaml), nil, nil)
		if err != nil {
			return nil, fmt.Errorf("decoding yaml file: %s\nerror: %w", yaml, err)
		}

		switch policy := obj.(type) {
		case T:
			output = append(output, policy)
		default:
			return nil, fmt.Errorf("unknown type '%s' in: %s", kind.Kind, yaml)
		}
	}

	return output, nil
}

func curlCmdVerbose(extra string) string {
	return "curl -w '%{local_ip}:%{local_port} -> %{remote_ip}:%{remote_port} = %{response_code}' --silent --fail --show-error " + extra
}

func curlCmd(extra string) string {
	return "curl --silent --fail --show-error " + extra
}
