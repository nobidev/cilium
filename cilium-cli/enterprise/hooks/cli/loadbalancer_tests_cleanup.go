// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/enterprise/hooks/cli/ilb"
	ilbCli "github.com/cilium/cilium/cilium-cli/enterprise/hooks/cli/ilb"
	"github.com/cilium/cilium/pkg/versioncheck"
)

func newCmdLoadbalancerTestCleanup() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Cleanup Loadbalancer test resources",
		Long:  "",
		RunE: func(c *cobra.Command, _ []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()
			c.SetContext(ctx)

			lbTestRun := ilbCli.NewLBTestRun(c.Context(), ciliumNamespace(c))
			ciliumCli, k8sCli := ilbCli.NewCiliumAndK8sCli(lbTestRun)
			dockerCli := ilbCli.NewDockerCli(lbTestRun)

			c.Println("Deleting K8s Namespaces ...")
			ns, err := k8sCli.CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=true", ilbCli.TestResourceLabelName)})
			if err != nil {
				return err
			}

			for _, n := range ns.Items {
				if err := k8sCli.CoreV1().Namespaces().Delete(ctx, n.Name, metav1.DeleteOptions{}); err != nil {
					return err
				}
			}

			c.Println("Deleting K8s BGP resources ...")
			if err := ciliumCli.IsovalentV1().IsovalentBGPAdvertisements().DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=true", ilbCli.TestResourceLabelName)}); err != nil {
				return err
			}

			if err := ciliumCli.IsovalentV1().IsovalentBGPPeerConfigs().DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=true", ilbCli.TestResourceLabelName)}); err != nil {
				return err
			}

			if err := ciliumCli.IsovalentV1().IsovalentBGPClusterConfigs().DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=true", ilbCli.TestResourceLabelName)}); err != nil {
				return err
			}

			if err := ciliumCli.IsovalentV1alpha1().IsovalentBFDProfiles().DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=true", ilbCli.TestResourceLabelName)}); err != nil {
				return err
			}

			c.Println("Deleting K8s LB IPAM resources ...")
			minVersion := ">=1.18.0"
			currentVersion := ilb.GetCiliumVersionRaw(ctx, lbTestRun, k8sCli, ciliumNamespace(c))

			if versioncheck.MustCompile(minVersion)(currentVersion) {
				if err := ciliumCli.CiliumV2().CiliumLoadBalancerIPPools().DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=true", ilbCli.TestResourceLabelName)}); err != nil {
					return err
				}
			} else {
				if err := ciliumCli.CiliumV2alpha1().CiliumLoadBalancerIPPools().DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=true", ilbCli.TestResourceLabelName)}); err != nil {
					return err
				}
			}

			c.Println("Deleting Docker containers ...")
			if err := dockerCli.DeleteAllContainers(ctx); err != nil {
				return err
			}

			return nil
		},
	}

	return cmd
}
