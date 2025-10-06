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

	k8s "github.com/cilium/cilium/pkg/k8s/slim/k8s/clientset"
)

func IsSingleNode() bool {
	return FlagMode == "single-node"
}

func useRemoteAddressEnabled() bool {
	return FlagUseRemoteAddress
}

func useRemoteAddressDisabled() bool {
	return !FlagUseRemoteAddress
}

func xffNumTrustedHopsEnabled() bool {
	return FlagXffNumTrustedHops > 0
}

func xffNumTrustedHopsDisabled() bool {
	return FlagXffNumTrustedHops <= 0
}

func getSingleNodeIPAddr() string {
	return FlagSingleNodeIPAddr
}

func getSingleNodeIPv6Addr() string {
	return FlagSingleNodeIPv6Addr
}

func skipIfOnSingleNode(msg string) bool {
	if IsSingleNode() {
		fmt.Printf("skipping due to single-mode: %s\n", msg)
		return true
	}

	return false
}

func skipIfNotUseRemoteAddress(msg string) bool {
	if useRemoteAddressDisabled() {
		fmt.Printf("skipping due to not using remote address: %s\n", msg)
		return true
	}

	return false
}

func SetupSingleNodeMode(ctx context.Context, dockerCli *dockerCli, k8sCli *k8s.Clientset) error {
	if FlagSingleNodeIPAddr != "" {
		return nil
	}

	if err := dockerCli.EnsureImage(ctx, FlagUtilsImage); err != nil {
		return fmt.Errorf("failed to ensure %s image: %w", FlagUtilsImage, err)
	}

	ips, err := getT1NodeIPs(ctx, k8sCli)
	if err != nil {
		return fmt.Errorf("failed to derive T1 node IP addrs: %w", err)
	}

	if err := deriveSingleNodeIP(ctx, dockerCli, ips[0]); err != nil {
		return fmt.Errorf("failed to derive single-node IP addr (you can set -single-node-ip): %w", err)
	}

	fmt.Printf("Derived single-node IP addr: %s\n", getSingleNodeIPAddr())

	return nil
}

func deriveSingleNodeIP(ctx context.Context, dockerCli *dockerCli, t1NodeIPAddr string) error {
	name := "single-node-ip"

	// It will run in the single-node's host netns
	_, _, _, err := dockerCli.createContainer(ctx, name, FlagUtilsImage, nil, "", false, []string{"sleep", "infinity"}, nil)
	if err != nil {
		return fmt.Errorf("failed to start %s: %w", name, err)
	}
	defer dockerCli.deleteContainer(ctx, name)
	ip, _, err := dockerCli.ContainerExec(ctx, name,
		[]string{
			"/bin/sh", "-c",
			fmt.Sprintf("ip -4 route get %s | grep -o 'src [0-9\\.]*' | cut -d' ' -f2", t1NodeIPAddr),
		})
	ip = strings.TrimSpace(ip)
	if err != nil {
		return fmt.Errorf("failed to get route to %s: %w", t1NodeIPAddr, err)
	}

	FlagSingleNodeIPAddr = ip

	return nil
}
