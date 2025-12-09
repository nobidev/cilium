// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/cilium-cli/cli"
	"github.com/cilium/cilium/cilium-cli/defaults"
	enterpriseDefaults "github.com/cilium/cilium/cilium-cli/enterprise/defaults"
	"github.com/cilium/cilium/cilium-cli/enterprise/hooks/cli/privnet"
	enterpriseK8s "github.com/cilium/cilium/cilium-cli/enterprise/hooks/k8s"
	"github.com/cilium/cilium/cilium-cli/k8s"
)

func newClient(params cli.RootParameters) (*enterpriseK8s.EnterpriseClient, error) {
	ossClient, err := k8s.NewClient(
		params.ContextName,
		params.KubeConfig,
		params.Namespace,
		params.ImpersonateAs,
		params.ImpersonateGroups,
	)
	if err != nil {
		return &enterpriseK8s.EnterpriseClient{}, err
	}

	return enterpriseK8s.NewEnterpriseClient(ossClient)
}

func newCmdPrivNetTest() *cobra.Command {
	var params privnet.Params

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Run private network tests",
		Long:  "",
		RunE: func(c *cobra.Command, _ []string) error {
			params.CiliumNamespace = cli.RootParams.Namespace

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()
			c.SetContext(ctx)

			clusterClient, err := enterpriseK8s.NewEnterpriseClient(cli.RootK8sClient)
			if err != nil {
				return fmt.Errorf("failed to construct local client: %w", err)
			}

			inbClients := make([]*enterpriseK8s.EnterpriseClient, len(params.INBContexts))
			for i, context := range params.INBContexts {
				rootParams := cli.RootParameters{
					ContextName:       context,
					Namespace:         cli.RootParams.Namespace,
					ImpersonateAs:     cli.RootParams.ImpersonateAs,
					ImpersonateGroups: cli.RootParams.ImpersonateGroups,
					KubeConfig:        cli.RootParams.KubeConfig,
				}
				inbClients[i], err = newClient(rootParams)
				if err != nil {
					return fmt.Errorf("failed to construct INB client %q: %w", context, err)
				}
			}

			t := privnet.NewTestRun(ctx, cancel, params, clusterClient, inbClients)
			err = t.SetupAndValidate(ctx)
			if err != nil {
				return err
			}

			defer func() {
				// Use a separate context, as we want cleanup to run if terminating
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				t.Cleanup(ctx)
				cancel()
			}()

			vmClientA := t.VM(privnet.NetworkA, privnet.ClientVM(privnet.NetworkA))
			vmEchoA := t.VM(privnet.NetworkA, privnet.EchoVM(privnet.NetworkA))
			vmEchoOtherA := t.VM(privnet.NetworkA, privnet.EchoOtherVM(privnet.NetworkA))

			vmClientB := t.VM(privnet.NetworkB, privnet.ClientVM(privnet.NetworkB))
			vmEchoOtherB := t.VM(privnet.NetworkB, privnet.EchoOtherVM(privnet.NetworkB))

			vmClientC := t.VM(privnet.NetworkC, privnet.ClientVM(privnet.NetworkC))
			vmEchoOtherC := t.VM(privnet.NetworkC, privnet.EchoOtherVM(privnet.NetworkC))
			podEchoOtherC := t.VirtLauncherPodForVM(vmEchoOtherC)

			externalTarget := params.ExternalTarget
			externalIPTarget := params.ExternalIPTarget

			t.Run(ctx, privnet.NewClientToEcho(t, vmClientA, vmEchoA), privnet.ExpectationOK)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientA, vmEchoOtherA), privnet.ExpectationOK)

			t.Run(ctx, privnet.NewClientToEcho(t, vmClientA, vmEchoOtherB), privnet.ExpectationCurlTimeout)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientB, vmEchoOtherB), privnet.ExpectationOK)
			t.Run(ctx, privnet.NewClientToEcho(t, vmClientC, vmEchoOtherC), privnet.ExpectationOK)

			// Traffic to world with DNS resolution should not be allowed from private network, since it does not have
			// a route for it.
			t.Run(ctx, privnet.NewClientToWorld(t, vmClientA, externalTarget), privnet.ExpectationCurlTimeout)

			// Traffic to world should not be allowed from private network, since it does not have
			// a route for it.
			t.Run(ctx, privnet.NewClientToWorld(t, vmClientA, externalIPTarget), privnet.ExpectationCurlTimeout)

			// Network C has default route via the INB, which can exit to the world.
			t.Run(ctx, privnet.NewClientToWorld(t, vmClientC, externalTarget), privnet.ExpectationOK)

			// Ensure traffic via P-IP is dropped
			t.Run(ctx, privnet.NewClientToPod(t, vmClientA, podEchoOtherC), privnet.ExpectationCurlTimeout)

			// Allow EchoServerPort as toPort in ingress policy for ext VMs
			if err := t.ApplyExternalEndpointIngressPolicies(ctx, privnet.EchoServerPort); err != nil {
				return err
			}
			for net := range t.Networks() {
				for ext := range t.External(net) {
					t.Run(ctx, privnet.NewClientToEcho(t, t.VM(net, privnet.ClientVM(net)), ext), privnet.ExpectationOK)
				}
			}

			// change port to not match on client connection.
			if err := t.ApplyExternalEndpointIngressPolicies(ctx, 9999); err != nil {
				return err
			}
			// connectivity fails
			for net := range t.Networks() {
				for ext := range t.External(net) {
					t.Run(ctx, privnet.NewClientToEcho(t, t.VM(net, privnet.ClientVM(net)), ext), privnet.ExpectationCurlTimeout)
				}
			}

			// Ensure traffic to unknown destinations works (policies don't apply here).
			for net := range t.Networks() {
				for _, dst := range privnet.UnknownDestinations[net] {
					t.Run(ctx, privnet.NewClientToEcho(t, t.VM(net, privnet.ClientVM(net)), dst), privnet.ExpectationOK)
				}
			}

			// Remove all policies before proceeding with the INB failover tests,
			// unless the context got canceled, in which case we let the deferred
			// function take care of it.
			if ctx.Err() == nil {
				t.Cleanup(ctx)
			}

			// Trigger a bunch of failovers.
			for inb := range t.INBNodeNames() {
				t.Run(ctx, privnet.NewFailover(t, inb), privnet.ExpectationOK)
			}

			// Check connectivity to external endpoints again.
			for net := range t.Networks() {
				for ext := range t.External(net) {
					t.Run(ctx, privnet.NewClientToEcho(t, t.VM(net, privnet.ClientVM(net)), ext), privnet.ExpectationOK)
				}
			}

			if t.Failed() {
				return errors.New("one or more tests failed")
			}

			return nil
		},
	}
	cmd.Flags().BoolVarP(&params.Debug, "debug", "d", false, "Show debug messages")
	cmd.Flags().StringVar(&params.TestNamespace, "test-namespace", defaults.ConnectivityCheckNamespace, "Namespace to perform the connectivity test in")
	cmd.Flags().StringVar(&params.AgentPodSelector, "agent-pod-selector", defaults.AgentPodSelector, "Label selector for Cilium Agent pods")
	cmd.Flags().StringVar(&params.ExternalTarget, "external-target", "one.one.one.one.", "External curl target")
	cmd.Flags().StringVar(&params.ExternalIPTarget, "external-ip-target", "1.1.1.1", "External curl IP target")
	cmd.Flags().StringSliceVar(&params.INBContexts, "inb-contexts", nil, "List of Kubernetes contexts of the Isovalent Network Bridges")
	cmd.Flags().StringVar(&params.VMImage, "vm-image", enterpriseDefaults.PrivnetTestImages["VMImage"], "Name of the VM image")
	cmd.Flags().StringVar(&params.ForkliftPlanName, "forklift-plan-name", "mock", "Name of the forklift/MTV plan")

	return cmd
}
