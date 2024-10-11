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
	accessLogRequestIdFilter              string
	accessLogVIPAndPortFilter             string
	accessLogGenericFilters               []string
	accessLogProtocolsFilter              []string
	accessLogIncludeHTTPHealthCheckFilter bool
)

func newCmdLoadbalancerT2AccesslogStreamer() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "accesslog",
		Short: "Display Loadbalancer T2 access log",
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

						if !strings.Contains(logLine, "Z][access]") {
							continue
						}

						if includeAccesslogLine(logLine) {
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

	cmd.Flags().StringVar(&accessLogRequestIdFilter, "request-id", "", "Request id to filter the access log for")
	cmd.Flags().StringVar(&accessLogVIPAndPortFilter, "vip-and-port", "", "VIP and Port to filter the access log for (VIP:PORT)")
	cmd.Flags().StringSliceVar(&accessLogGenericFilters, "filters", []string{}, "Attribute filters to filter the access log for (attribute=value,attribute2=value2). All of the filters must match.")
	cmd.Flags().StringSliceVar(&accessLogProtocolsFilter, "protocols", []string{"tcp", "tls", "http"}, "Filter for the provided protocols")
	cmd.Flags().BoolVar(&accessLogIncludeHTTPHealthCheckFilter, "healthcheck", false, "Include HTTP Healthcheck accesslog")

	return cmd
}

func includeAccesslogLine(logLine string) bool {
	// filter for log type (OR)
	logTypes := []string{}

	logTypes = append(logTypes, accessLogProtocolsFilter...)

	if accessLogIncludeHTTPHealthCheckFilter {
		logTypes = append(logTypes, "healthcheck")
	}

	matchesOneLogType := false
	for _, lt := range logTypes {
		if strings.Contains(logLine, fmt.Sprintf("Z][access][%s]", lt)) {
			matchesOneLogType = true
		}
	}

	if len(logTypes) > 0 && !matchesOneLogType {
		return false
	}

	// filter for log attributes (AND)
	attributeFilters := map[string]string{}

	if accessLogRequestIdFilter != "" {
		attributeFilters["http.req.x-request-id"] = accessLogRequestIdFilter
	}

	if accessLogVIPAndPortFilter != "" {
		attributeFilters["downstream.local-address"] = accessLogVIPAndPortFilter
	}

	for _, f := range accessLogGenericFilters {
		attrValue := strings.Split(f, "=")
		if len(attrValue) == 2 {
			attributeFilters[attrValue[0]] = attrValue[1]
		}
	}

	allAttributeFiltersMatched := true
	for k, v := range attributeFilters {
		if !strings.Contains(logLine, fmt.Sprintf("%s=\"%s\"", k, v)) {
			allAttributeFiltersMatched = false
			break
		}
	}

	return allAttributeFiltersMatched
}
