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
	"flag"
	"fmt"
	"log"
	"strings"
	"testing"

	k8s "github.com/cilium/cilium/pkg/k8s/slim/k8s/clientset"
)

var flagMode = flag.String("mode", "multi-node", "Testing mode ('multi-node' or 'single-node'). 'multi-node' deploys client and LB app containers in separate network namespaces (to simulate multi-node LB environments). 'single-node' deploys the containers on a single node in the same host network namespace.")
var flagSingleNodeIPAddr = flag.String("single-node-ip", "", "The IP addr of the test runner node. The IP addr should be reachable by T1 and T2 nodes. Required when --mode=single-node.")

func isSingleNode() bool {
	return *flagMode == "single-node"
}

func getSingleNodeIPAddr() string {
	return *flagSingleNodeIPAddr
}

func skipIfOnSingleNode(t *testing.T, msg string) {
	if isSingleNode() {
		t.Skipf("skipping due to single-mode: %s", msg)
	}
}

func setupSingleNodeMode(dockerCli *dockerCli, k8sCli *k8s.Clientset) error {
	if *flagSingleNodeIPAddr != "" {
		return nil
	}

	if err := dockerCli.ensureImage(context.Background(), *flagUtilsImage); err != nil {
		return fmt.Errorf("failed to ensure %s image: %w", *flagUtilsImage, err)
	}

	ips, err := getT1NodeIPs(k8sCli)
	if err != nil {
		return fmt.Errorf("failed to derive T1 node IP addrs: %w", err)
	}

	if err := deriveSingleNodeIP(dockerCli, ips[0]); err != nil {
		return fmt.Errorf("failed to derive single-node IP addr (you can set -single-node-ip): %w", err)
	}

	log.Printf("Derived single-node IP addr: %s", getSingleNodeIPAddr())

	return nil
}

func deriveSingleNodeIP(dockerCli *dockerCli, t1NodeIPAddr string) error {
	name := "single-node-ip"

	// It will run in the single-node's host netns
	_, _, err := dockerCli.createContainer(context.Background(), name, *flagUtilsImage, nil, "", false, []string{"sleep", "infinity"}, nil)
	if err != nil {
		return fmt.Errorf("failed to start %s: %w", name, err)
	}
	defer dockerCli.deleteContainer(context.Background(), name)
	ip, _, err := dockerCli.ContainerExec(context.Background(), name,
		[]string{
			"/bin/sh", "-c",
			fmt.Sprintf("ip -4 route get %s | grep -o 'src [0-9\\.]*' | cut -d' ' -f2", t1NodeIPAddr),
		})
	ip = strings.TrimSpace(ip)
	if err != nil {
		return fmt.Errorf("failed to get route to %s: %w", t1NodeIPAddr, err)
	}

	*flagSingleNodeIPAddr = ip

	return nil
}
