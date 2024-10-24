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
	"os"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Execute Isovalent Loadbalancer E2E Tests
//
// Usage:
//
// DOCKER_API_VERSION=1.45 LOADBALANCER_TESTS=true go test -count=1 -v ./enterprise/test/ilb/... [flags]
//
// Flags:
//
//  -app-image string
//        app container image name (default "quay.io/isovalent-dev/lb-healthcheck-app:v0.0.8")
//  -cleanup
//        Cleanup created resources after each test case run (default true)
//  -client-image string
//        client container image name (default "quay.io/isovalent-dev/lb-frr-client:v0.0.3")
//  -mode string
//        Testing mode ('multi-node' or 'single-node'). 'multi-node' deploys client and LB app containers in separate network namespaces (to simulate multi-node LB environments). 'single-node' deploys the containers on a single node in the same host network namespace. (default "multi-node")
//  -single-node-ip string
//        The IP addr of the test runner node. The IP addr should be reachable by T1 and T2 nodes. Required when --mode=single-node.
//	-use-remote-address bool
//        Use remote address for client IP in HTTP requests (default true)
//  -xff-num-trusted-hops int
//        Number of trusted hops in X-Forwarded-For header (default 0)
// One can run in the --mode=single-node using a remote node for deploying client
// and LB app containers, and then running test requests from them. To do so,
// set DOCKER_HOST= to point to the remote node.

func TestMain(m *testing.M) {
	if os.Getenv("LOADBALANCER_TESTS") != "true" {
		fmt.Println("Skipping due to LOADBALANCER_TESTS!=true")
		return
	}

	flag.Parse()

	pf := &panicFataler{}

	if *flagMode != "single-node" && *flagMode != "multi-node" {
		pf.Fatalf("invalid --mode: %s", *flagMode)
	}

	ciliumCli, k8sCli := newCiliumAndK8sCli(pf)
	dockerCli := newDockerCli(pf)

	for _, img := range []string{*flagAppImage, *flagClientImage, *flagCoreDNSImage} {
		if err := dockerCli.ensureImage(context.Background(), img); err != nil {
			pf.Fatalf("failed to ensure Docker image %s: %s", img, err)
		}
	}

	if isSingleNode() {
		if err := setupSingleNodeMode(dockerCli, k8sCli); err != nil {
			pf.Fatalf("failed to set up single-node mode: %s", err)
		}
	}

	// Create LBIPPool (it is shared among all test cases)

	lbIPPool := lbIPPool(lbIPPoolName, "100.64.0.0/24")
	if err := ciliumCli.ensureLBIPPool(context.Background(), lbIPPool); err != nil {
		panic(fmt.Sprintf("Failed to ensure LBIPPool (%s): %s", lbIPPoolName, err))
	}
	defer maybeCleanup(func() error {
		return ciliumCli.DeleteLBIPPool(context.Background(), lbIPPoolName, metav1.DeleteOptions{})
	})

	// Create IsovalentBGPClusterConfig (each test case will append its peer to it)
	if err := ciliumCli.ensureBGPClusterConfig(context.Background()); err != nil {
		panic(fmt.Sprintf("Failed to install BGP peering: %s", err))
	}
	defer maybeCleanup(func() error {
		return ciliumCli.deleteBGPClusterConfig(context.Background())
	})

	// Run tests

	m.Run()
}
