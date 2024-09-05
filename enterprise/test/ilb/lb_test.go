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

const (
	containerNetwork = "kind-cilium"

	appImage    = "quay.io/isovalent-dev/lb-healthcheck-app:v0.0.4"
	clientImage = "quay.io/isovalent-dev/lb-frr-client:v0.0.2"

	lbIPPoolName = "lb-pool"
)

var cleanup = flag.Bool("cleanup", true, "Cleanup created resources after each test case run")

func TestMain(m *testing.M) {
	if os.Getenv("LOADBALANCER_TESTS") != "true" {
		fmt.Println("Skipping due to LOADBALANCER_TESTS!=true")
		return
	}

	flag.Parse()

	pf := &panicFataler{}

	ciliumCli, _ := newCiliumAndK8sCli(pf)
	dockerCli := newDockerCli(pf)

	for _, img := range []string{appImage, clientImage} {
		if err := dockerCli.ensureImage(context.Background(), img); err != nil {
			panic(fmt.Sprintf("Failed to ensure Docker image %s: %s", img, err))
		}
	}

	// Test retrieving T1 LB IP addr

	if _, err := getT1NodeIPs(dockerCli); err != nil {
		panic(fmt.Sprintf("Failed to retrieve T1 LB IPs: %s", err))
	}

	// Create LBIPPool (it is shared among all test cases)

	lbIPPool := lbIPPool(lbIPPoolName, "100.64.0.0/24")
	if err := ciliumCli.ensureLBIPPool(context.Background(), lbIPPool); err != nil {
		panic(fmt.Sprintf("Failed to ensure LBIPPool (%s): %s", lbIPPoolName, err))
	}
	defer maybeCleanup(func() error {
		return ciliumCli.DeleteLBIPPool(context.Background(), lbIPPoolName, metav1.DeleteOptions{})
	})

	// Create CiliumBGPPeeringPolicy and BFD (each test case will append its peer to it)
	if err := ciliumCli.ensureBGPPeeringPolicyAndBFD(context.Background()); err != nil {
		panic(fmt.Sprintf("Failed to install BGP peering: %s", err))
	}
	defer maybeCleanup(func() error {
		return ciliumCli.deleteBGPPeeringPolicyAndBFD(context.Background())
	})

	// Run tests

	m.Run()
}

func maybeCleanupT(f func() error, t *testing.T) {
	if *cleanup {
		t.Cleanup(func() {
			if err := f(); err != nil {
				fmt.Printf("cleanup failed %s\n", err)
			}
		})
	}
}

func maybeCleanup(f func() error) {
	if *cleanup {
		if err := f(); err != nil {
			fmt.Printf("cleanup failed: %s\n", err)
		}
	}
}

var _ fataler = &panicFataler{}

type panicFataler struct{}

func (p *panicFataler) Fatalf(format string, args ...any) {
	panic(fmt.Sprintf(format, args...))
}
