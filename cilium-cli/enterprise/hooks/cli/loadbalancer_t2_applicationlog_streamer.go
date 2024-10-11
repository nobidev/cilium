// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/api"
)

var (
	applicationLogConnectionIDsFilter []string
	applicationLogPodNameFilter       string
)

func newCmdLoadbalancerT2ApplicationlogStreamer() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "applicationlog",
		Short: "Display Loadbalancer T2 application log",
		Long:  "",
		RunE: func(c *cobra.Command, _ []string) error {
			k8sClient, _ := api.GetK8sClientContextValue(c.Context())

			pods, err := k8sClient.ListPods(c.Context(), "kube-system", metav1.ListOptions{
				LabelSelector: "name=cilium-envoy",
			})
			if err != nil {
				return fmt.Errorf("failed to list T2 Envoy pods: %w", err)
			}

			errGrp, ctx := errgroup.WithContext(c.Context())

			for _, p := range pods.Items {
				if applicationLogPodNameFilter != "" && p.Name != applicationLogPodNameFilter {
					continue
				}

				errGrp.Go(func() error {
					r := k8sClient.Clientset.CoreV1().Pods(p.Namespace).GetLogs(p.Name, &corev1.PodLogOptions{
						Follow: true,
					})
					s, err := r.Stream(ctx)
					if err != nil {
						return fmt.Errorf("failed to open log stream for pod %q: %w", p.Name, err)
					}

					defer s.Close()
					scanner := bufio.NewScanner(s)
					for scanner.Scan() {
						logLine := scanner.Text()

						if strings.Contains(logLine, "Z][access]") {
							continue
						}

						if includeApplicationlogLine(logLine) {
							if _, err = io.Copy(os.Stdout, strings.NewReader(fmt.Sprintf("[%s] %s\n", p.Name, logLine))); err != nil {
								return fmt.Errorf("failed to copy: %w", err)
							}
						}
					}

					return nil
				})
			}

			if err := errGrp.Wait(); err != nil {
				return fmt.Errorf("failed to stream logs: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().StringSliceVar(&applicationLogConnectionIDsFilter, "connection-ids", []string{}, "List of connection ids to filter the application log for")
	cmd.Flags().StringVar(&applicationLogPodNameFilter, "pod", "", "Filter the application log for a given Envoy Pod Name")

	return cmd
}

func includeApplicationlogLine(logLine string) bool {
	// filter for connections (OR)
	matchesOneConnection := false
	for _, id := range applicationLogConnectionIDsFilter {
		if strings.Contains(logLine, fmt.Sprintf("[Tags: \"ConnectionId\":\"%s\"", id)) {
			matchesOneConnection = true
		}
	}

	if len(applicationLogConnectionIDsFilter) > 0 && !matchesOneConnection {
		return false
	}

	return true
}
