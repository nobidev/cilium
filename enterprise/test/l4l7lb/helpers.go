//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package l4l7lb

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	docker_client "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	cilium_clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
)

const (
	shortTimeout = 30 * time.Second
	pollInterval = 1 * time.Second
)

type clients struct {
	ciliumClientset *cilium_clientset.Clientset
	dockerClient    *docker_client.Client
}

func newClients() (*clients, error) {
	var clients clients

	kubeConfigPath := filepath.Join(homedir.HomeDir(), ".kube", "config")

	restConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		panic(err)
	}

	httpClient, err := rest.HTTPClientFor(restConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create k8s REST client: %w", err)
	}

	clients.ciliumClientset, err = cilium_clientset.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		return nil, fmt.Errorf("unable to create cilium k8s client: %w", err)
	}

	clients.dockerClient, err = docker_client.NewClientWithOpts(docker_client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("Failed to open Docker client: %w", err)
	}

	return &clients, err
}

func (c *clients) CreateLBVIP(ctx context.Context, namespace string, obj *v1alpha1.LBVIP, opts v1.CreateOptions) error {
	_, err := c.ciliumClientset.IsovalentV1alpha1().LBVIPs(namespace).Create(ctx, obj, opts)
	return err
}

func (c *clients) DeleteLBVIP(ctx context.Context, namespace, name string, opts v1.DeleteOptions) error {
	return c.ciliumClientset.IsovalentV1alpha1().LBVIPs(namespace).Delete(ctx, name, opts)
}

func (c *clients) CreateLBFrontend(ctx context.Context, namespace string, obj *v1alpha1.LBFrontend, opts v1.CreateOptions) error {
	_, err := c.ciliumClientset.IsovalentV1alpha1().LBFrontends(namespace).Create(ctx, obj, opts)
	return err
}

func (c *clients) DeleteLBFrontend(ctx context.Context, namespace, name string, opts v1.DeleteOptions) error {
	return c.ciliumClientset.IsovalentV1alpha1().LBFrontends(namespace).Delete(ctx, name, opts)
}

func (c *clients) GetLBFrontend(ctx context.Context, namespace, name string, opts v1.GetOptions) (*v1alpha1.LBFrontend, error) {
	return c.ciliumClientset.IsovalentV1alpha1().LBFrontends(namespace).Get(ctx, name, opts)
}

func (c *clients) CreateLBBackend(ctx context.Context, namespace string, obj *v1alpha1.LBBackend, opts v1.CreateOptions) error {
	_, err := c.ciliumClientset.IsovalentV1alpha1().LBBackends(namespace).Create(ctx, obj, opts)
	return err
}

func (c *clients) DeleteLBBackend(ctx context.Context, namespace, name string, opts v1.DeleteOptions) error {
	return c.ciliumClientset.IsovalentV1alpha1().LBBackends(namespace).Delete(ctx, name, opts)
}

func (c *clients) CreateLBIPPool(ctx context.Context, obj *v2alpha1.CiliumLoadBalancerIPPool, opts v1.CreateOptions) error {
	_, err := c.ciliumClientset.CiliumV2alpha1().CiliumLoadBalancerIPPools().Create(ctx, obj, opts)
	return err
}

func (c *clients) DeleteLBIPPool(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.ciliumClientset.CiliumV2alpha1().CiliumLoadBalancerIPPools().Delete(ctx, name, opts)
}

func (c *clients) GetContainerIP(ctx context.Context, containerName string) (string, error) {
	obj, err := c.dockerClient.ContainerInspect(ctx, containerName)
	if err != nil {
		return "", err
	}

	for _, network := range obj.NetworkSettings.Networks {
		return network.IPAddress, nil
	}

	return "", fmt.Errorf("no network found")
}

func (c *clients) WaitForLBVIP(ctx context.Context, namespace, name string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, shortTimeout)
	defer cancel()

	for {
		obj, err := c.GetLBFrontend(ctx, namespace, name, v1.GetOptions{})
		if err != nil {
			return "", err
		}

		if ip := obj.Status.Addresses.IPv4; ip != "" {
			return ip, nil
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

func (c *clients) ContainerExec(ctx context.Context, name string, cmds []string) (string, string, error) {
	var stdout, stderr bytes.Buffer

	execConfig := container.ExecOptions{
		AttachStderr: true,
		AttachStdout: true,
		Cmd:          cmds,
	}

	execID, err := c.dockerClient.ContainerExecCreate(ctx, name, execConfig)
	if err != nil {
		return "", "", nil
	}

	resp, err := c.dockerClient.ContainerExecAttach(ctx, execID.ID, container.ExecAttachOptions{})
	if err != nil {
		return "", "", err
	}
	defer resp.Close()

	_, err = stdcopy.StdCopy(&stdout, &stderr, resp.Reader)
	if err != nil {
		return stdout.String(), stderr.String(), err
	}

	inspect, err := c.dockerClient.ContainerExecInspect(ctx, execID.ID)
	if err != nil {
		return stdout.String(), stderr.String(), err
	}

	if inspect.ExitCode != 0 {
		return stdout.String(), stderr.String(), fmt.Errorf("cmd failed: %d", inspect.ExitCode)
	}

	return stdout.String(), stderr.String(), err
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

func curlCmd(extra string) string {
	return "curl -w '%{local_ip}:%{local_port} -> %{remote_ip}:%{remote_port} = %{response_code}' --silent --fail --show-error " + extra
}
