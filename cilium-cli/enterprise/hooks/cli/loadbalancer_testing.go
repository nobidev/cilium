// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"context"
	"fmt"

	ilbCli "github.com/cilium/cilium/cilium-cli/enterprise/hooks/cli/ilb"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Execute Isovalent Loadbalancer E2E Tests
//
// Usage:
//
// DOCKER_API_VERSION=1.45 LOADBALANCER_TESTS=true go test -count=1 -v [go-test-flags] ./enterprise/test/ilb/... [ilb-test-flags]
//
// ILB test flags:
//
//  -app-image string
//        app container image name (default "quay.io/isovalent-dev/lb-healthcheck-app:v0.0.10")
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
//
// One can run in the --mode=single-node using a remote node for deploying client
// and LB app containers, and then running test requests from them. To do so,
// set DOCKER_HOST= to point to the remote node.
//
// To filter for a specific test, one can use the go test flag `-run <TestName>`.

var tests = []func(){
	ilbCli.TestBasicAuth,
	ilbCli.TestBGPHealthCheck,
	ilbCli.TestDNSBackend,
	ilbCli.TestHeadlessService,
	ilbCli.TestHTTPAndT2HealthChecks,
	ilbCli.TestHTTP2,
	ilbCli.TestHTTPPath,
	ilbCli.TestHTTPRoutes,
	ilbCli.TestHTTPClientIP,
	ilbCli.TestHTTPConnectionFiltering,
	ilbCli.TestHTTPProxyProtocol,
	ilbCli.TestHTTPRouteRatelimiting,
	ilbCli.TestHTTPApplicationRatelimiting,
	ilbCli.TestHTTPRequestFiltering,
	ilbCli.TestHTTPS,
	ilbCli.TestHTTPSRoutes,
	ilbCli.TestHTTPS_H2,
	ilbCli.TestHTTPSConnectionFiltering,
	ilbCli.TestHTTPSRouteRatelimiting,
	ilbCli.TestHTTPSApplicationRatelimiting,
	ilbCli.TestHTTPSRequestFiltering,
	ilbCli.TestJWTAuth,
	ilbCli.TestPersistentBackendWithCookie,
	ilbCli.TestPersistentBackendWithSourceIP,
	ilbCli.TestTCPProxyConnectionFiltering,
	ilbCli.TestTCPProxyPersistentBackend,
	ilbCli.TestTCPProxyPersistentBackend_Fail_T1Only,
	ilbCli.TestTCPProxyRatelimiting,
	ilbCli.TestTCPProxyRatelimiting_Fail_T1Only,
	ilbCli.TestTCPProxy,
	ilbCli.TestTLSPassthrough,
	ilbCli.TestTLSPassthroughConnectionFiltering,
	ilbCli.TestTLSPassthroughRatelimiting,
	ilbCli.TestTLSProxyTCPBackend,
	ilbCli.TestTLSProxyTLSBackend,
	ilbCli.TestTLSProxyConnectionFiltering,
	ilbCli.TestTLSProxyRatelimiting,
	ilbCli.TestUDPProxy,
	ilbCli.TestSharedVIP,
	ilbCli.TestRequestedVIP,
}

func newCmdLoadbalancerTest() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Run Loadbalancer tests",
		Long:  "",
		RunE: func(c *cobra.Command, _ []string) error {
			if ilbCli.FlagMode != "single-node" && ilbCli.FlagMode != "multi-node" {
				return fmt.Errorf("invalid --mode: %s", ilbCli.FlagMode)
			}

			ciliumCli, k8sCli := ilbCli.NewCiliumAndK8sCli()
			dockerCli := ilbCli.NewDockerCli()

			for _, img := range []string{ilbCli.FlagAppImage, ilbCli.FlagClientImage, ilbCli.FlagCoreDNSImage, ilbCli.FlagNginxImage} {
				if err := dockerCli.EnsureImage(context.Background(), img); err != nil {
					return fmt.Errorf("failed to ensure Docker image %s: %w", img, err)
				}
			}

			if ilbCli.IsSingleNode() {
				if err := ilbCli.SetupSingleNodeMode(dockerCli, k8sCli); err != nil {
					return fmt.Errorf("failed to set up single-node mode: %w", err)
				}
			}

			// Create LBIPPool (it is shared among all test cases)

			lbIPPool := ilbCli.LbIPPool(ilbCli.LbIPPoolName, "100.64.0.0/24")
			if err := ciliumCli.EnsureLBIPPool(context.Background(), lbIPPool); err != nil {
				return fmt.Errorf("Failed to ensure LBIPPool (%s): %w", ilbCli.LbIPPoolName, err)
			}
			defer ilbCli.MaybeCleanup(func() error {
				return ciliumCli.DeleteLBIPPool(context.Background(), ilbCli.LbIPPoolName, metav1.DeleteOptions{})
			})

			// Create IsovalentBGPClusterConfig (each test case will append its peer to it)
			if err := ciliumCli.EnsureBGPClusterConfig(context.Background()); err != nil {
				return fmt.Errorf("Failed to install BGP peering: %w", err)
			}
			defer ilbCli.MaybeCleanup(func() error {
				return ciliumCli.DeleteBGPClusterConfig(context.Background())
			})

			// Run tests
			for _, test := range tests {
				test()
			}

			ilbCli.RunCleanups()

			return nil
		},
	}

	cmd.Flags().StringVar(&ilbCli.FlagAppImage, "app-image", "quay.io/isovalent-dev/lb-healthcheck-app:v0.0.10", "app container image name")
	cmd.Flags().StringVar(&ilbCli.FlagClientImage, "client-image", "quay.io/isovalent-dev/lb-frr-client:v0.0.3", "client container image name")
	cmd.Flags().StringVar(&ilbCli.FlagUtilsImage, "utils-image", "busybox:1.37.0-musl", "utils container image name")
	cmd.Flags().StringVar(&ilbCli.FlagCoreDNSImage, "coredns-image", "coredns/coredns:1.11.1", "coredns container image name")
	cmd.Flags().StringVar(&ilbCli.FlagNginxImage, "nginx-image", "library/nginx:1.27.2", "nginx container image name")

	cmd.Flags().BoolVar(&ilbCli.FlagCleanup, "cleanup", true, "Cleanup created resources after each test case run")
	// maybeSysdump is only effective when this option is specified.
	cmd.Flags().BoolVar(&ilbCli.FlagSysdumpOnFailure, "sysdump-on-failure", false, "Collect sysdump on test failure")

	// By default, we assume cilium-cli is in the PATH. In the CI, we may want to specify custom path.
	cmd.Flags().StringVar(&ilbCli.FlagCiliumCLIPath, "cilium-cli-path", "cilium", "cilium-cli binary path")

	cmd.Flags().StringVar(&ilbCli.FlagMode, "mode", "multi-node", "Testing mode ('multi-node' or 'single-node'). 'multi-node' deploys client and LB app containers in separate network namespaces (to simulate multi-node LB environments). 'single-node' deploys the containers on a single node in the same host network namespace.")
	cmd.Flags().StringVar(&ilbCli.FlagSingleNodeIPAddr, "single-node-ip", "", "The IP addr of the test runner node. The IP addr should be reachable by T1 and T2 nodes. Required when --mode=single-node.")

	// TODO (sayboras): Remove these flags once we have feature auto-detection
	cmd.Flags().BoolVar(&ilbCli.FlagUseRemoteAddress, "use-remote-address", false, "Use remote address for client IP in HTTP requests")
	cmd.Flags().IntVar(&ilbCli.FlagXffNumTrustedHops, "xff-num-trusted-hops", 2, "Number of trusted hops in X-Forwarded-For header")

	return cmd
}
