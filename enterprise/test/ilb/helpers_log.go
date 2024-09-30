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
	"strings"

	"github.com/docker/docker/api/types/container"

	"github.com/cilium/cilium/pkg/safeio"
)

func logContains(ctx context.Context, dockerCli *dockerCli, backendContainer dockerContainer, message string) func() error {
	return func() error {
		rc, err := dockerCli.ContainerLogs(ctx, backendContainer.id, container.LogsOptions{ShowStdout: true, ShowStderr: true})
		if err != nil {
			return fmt.Errorf("failed to get container logs: %w", err)
		}
		defer rc.Close()

		log, err := safeio.ReadAllLimit(rc, safeio.GB)
		if err != nil {
			return fmt.Errorf("failed to read container logs: %w", err)
		}

		if !strings.Contains(string(log), message) {
			return fmt.Errorf("container %q doesn't contain log message %q", backendContainer.id, message)
		}

		return nil
	}
}
