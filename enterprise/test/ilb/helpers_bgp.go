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
)

func getT1NodeIPs(dockerCli *dockerCli) ([]string, error) {
	// TODO maybe use "kubectl get nodes"
	ip, err := dockerCli.GetContainerIP(context.Background(), "kind-control-plane")
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve T1 LB IP: %w", err)
	}

	return []string{
		ip,
	}, nil
}

func getBGPNeighborString(f fataler, dockerCli *dockerCli) string {
	t1NodeIPs, err := getT1NodeIPs(dockerCli)
	if err != nil {
		f.Fatalf("failed to get T1 node ips: %s", err)
	}

	return strings.Join(t1NodeIPs, ";")
}
