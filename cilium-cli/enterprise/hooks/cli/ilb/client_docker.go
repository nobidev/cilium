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
	"fmt"
	"io"
	"path/filepath"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	docker_client "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"

	"github.com/cilium/cilium/pkg/safeio"
)

type dockerCli struct {
	*docker_client.Client
}

func NewDockerCli(f FailureReporter) *dockerCli {
	cli, err := docker_client.NewClientWithOpts(docker_client.FromEnv)
	if err != nil {
		f.Failedf("failed to open Docker client: %s", err)
	}

	return &dockerCli{cli}
}

func (c *dockerCli) GetContainerIPs(ctx context.Context, containerName string) (ipv4 string, ipv6 string, err error) {
	obj, err := c.ContainerInspect(ctx, containerName)
	if err != nil {
		return "", "", err
	}

	for _, network := range obj.NetworkSettings.Networks {
		return network.IPAddress, network.GlobalIPv6Address, nil
	}

	return "", "", fmt.Errorf("no network found")
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

func (c *dockerCli) ContainerExecDetached(ctx context.Context, name string, cmds []string) (io.Reader, error) {
	execConfig := container.ExecOptions{
		Detach:       true,
		Tty:          true, // prevents cryptic character at line start when copying to stdout
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          cmds,
	}

	execID, err := c.ContainerExecCreate(ctx, name, execConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to exec command: %w", err)
	}

	resp, err := c.ContainerExecAttach(ctx, execID.ID, container.ExecAttachOptions{
		Tty: true, // prevents cryptic character at line start when copying to stdout
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach: %w", err)
	}

	return resp.Reader, err
}

func (c *dockerCli) imageExists(ctx context.Context, img string) (bool, error) {
	images, err := c.ImageList(ctx, image.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("list images: %w", err)
	}

	for _, image := range images {
		for _, tag := range image.RepoTags {
			if tag == img {
				return true, nil
			}
		}
	}

	return false, nil
}

func (c *dockerCli) EnsureImage(ctx context.Context, img string) error {
	if !FlagEnsureImages {
		return nil
	}

	if exists, err := c.imageExists(ctx, img); err != nil || exists {
		return err
	}

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

func (c *dockerCli) createContainer(ctx context.Context, name, img string, env []string, networkName string, privileged bool, cmd []string, preStart func(*dockerCli, string) error) (string, string, string, error) {
	c.ContainerRemove(ctx, name, container.RemoveOptions{Force: true})

	hostCfg := &container.HostConfig{
		Privileged: privileged,
	}
	networkCfg := &network.NetworkingConfig{
		EndpointsConfig: map[string]*network.EndpointSettings{
			networkName: {},
		},
	}

	if IsSingleNode() {
		// When --mode=single-node, we deploy all containers (client and LB backend)
		// on the same node. Because T1/T2 LB nodes are unware of IP addrs of
		// the containers, we deploy them in the host network namespace.
		hostCfg.NetworkMode = "host"
		networkCfg = nil
	}

	resp, err := c.ContainerCreate(ctx,
		//exhaustruct:ignore
		&container.Config{
			Image:  img,
			Env:    env,
			Cmd:    cmd,
			Labels: map[string]string{TestResourceLabelName: "true"},
		},
		hostCfg,
		networkCfg,
		nil,
		name,
	)
	if err != nil {
		return "", "", "", err
	}

	if preStart != nil {
		if err := preStart(c, resp.ID); err != nil {
			return "", "", "", fmt.Errorf("preStart failed: %w", err)
		}
	}

	if err := c.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return "", "", "", err
	}

	// In the single node mode, the container runs in the host netns. Hence, it's IP
	// addr is of the host.
	containerIPv4 := getSingleNodeIPAddr()
	containerIPv6 := getSingleNodeIPv6Addr()
	if !IsSingleNode() {
		ipv4, ipv6, err := c.GetContainerIPs(ctx, resp.ID)
		if err != nil {
			return "", "", "", err
		}

		containerIPv4 = ipv4
		containerIPv6 = ipv6
	}

	return resp.ID, containerIPv4, containerIPv6, nil
}

func (c *dockerCli) deleteContainer(ctx context.Context, name string) error {
	return c.ContainerRemove(ctx, name, container.RemoveOptions{Force: true})
}

func (c *dockerCli) DeleteAllContainers(ctx context.Context) error {
	containers, err := c.ContainerList(ctx, container.ListOptions{
		Filters: filters.NewArgs(filters.KeyValuePair{
			Key:   "label",
			Value: fmt.Sprintf("%s=true", TestResourceLabelName),
		}),
	})
	if err != nil {
		return fmt.Errorf("failed to list test containers: %w", err)
	}

	for _, ct := range containers {
		if err := c.ContainerRemove(ctx, ct.ID, container.RemoveOptions{Force: true}); err != nil {
			return fmt.Errorf("failed to delete test container %s: %w", ct.ID, err)
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

func createTAR(content []byte, path string) (io.Reader, error) {
	var buf bytes.Buffer

	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{
		Name: filepath.Base(path),
		Mode: 0o644,
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
