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
	"io"
)

type dockerContainer struct {
	id        string
	ipv4      string
	ipv6      string
	port      uint32
	dockerCli *dockerCli
}

func (c *dockerContainer) ID() string {
	return c.id
}

func (c *dockerContainer) IP() string {
	return c.ipv4
}

func (c *dockerContainer) Exec(ctx context.Context, cmd string) (string, string, error) {
	return c.dockerCli.ContainerExec(ctx, c.id, []string{"sh", "-c", cmd})
}

func (c *dockerContainer) ExecDetached(ctx context.Context, cmd []string) (io.Reader, error) {
	return c.dockerCli.ContainerExecDetached(ctx, c.id, cmd)
}

func (c *dockerContainer) Copy(ctx context.Context, content []byte, dstFile, dstDir string) error {
	return c.dockerCli.copyToContainer(ctx, c.id, content, dstFile, dstDir)
}

func (c *dockerContainer) Kill(ctx context.Context, sig string) error {
	return c.dockerCli.ContainerKill(ctx, c.id, sig)
}
