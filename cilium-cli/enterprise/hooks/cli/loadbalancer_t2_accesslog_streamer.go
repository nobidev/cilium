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
)

var (
	accessLogRequestIdFilter              string
	accessLogVIPAndPortFilter             string
	accessLogGenericFilters               []string
	accessLogProtocolsFilter              []string
	accessLogIncludeHTTPHealthCheckFilter bool
	accessLogFollow                       bool
	accessLogFiles                        []string
)

func newCmdLoadbalancerT2AccesslogStreamer() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "accesslog",
		Short: "Display Loadbalancer T2 access log",
		Long:  "",
		RunE: func(c *cobra.Command, _ []string) error {
			var readers []reader
			var err error
			errGrp, ctx := errgroup.WithContext(c.Context())

			if len(accessLogFiles) == 0 {
				readers, err = podReaders(ctx, "", accessLogFollow)
			} else {
				readers, err = fileReaders(accessLogFiles)
			}
			if err != nil {
				return err
			}
			defer func() {
				for _, r := range readers {
					r.r.Close()
				}
			}()

			for _, r := range readers {
				errGrp.Go(func() error {
					scanner := bufio.NewScanner(r.r)
					for scanner.Scan() {
						logLine := scanner.Text()

						if !strings.Contains(logLine, "Z][access]") {
							continue
						}

						if includeAccesslogLine(logLine) {
							if _, err := io.Copy(os.Stdout, strings.NewReader(fmt.Sprintf("[%s] %s\n", r.name, logLine))); err != nil {
								return fmt.Errorf("failed to copy: %w", err)
							}
						}
					}

					return nil
				})
			}

			if err := errGrp.Wait(); err != nil {
				return fmt.Errorf("failed to read logs: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().StringSliceVar(&accessLogFiles, "files", nil, "Comma-separated list of access log files. If empty, logs will be retrieved from ILB Envoy pods")
	cmd.Flags().StringVar(&accessLogRequestIdFilter, "request-id", "", "Request id to filter the access log for")
	cmd.Flags().StringVar(&accessLogVIPAndPortFilter, "vip-and-port", "", "VIP and Port to filter the access log for (VIP:PORT)")
	cmd.Flags().StringSliceVar(&accessLogGenericFilters, "filters", []string{}, "Attribute filters to filter the access log for (attribute=value,attribute2=value2). All of the filters must match.")
	cmd.Flags().StringSliceVar(&accessLogProtocolsFilter, "protocols", []string{"udp", "tcp", "tls_passthrough", "tls", "https", "http"}, "Filter for the provided protocols")
	cmd.Flags().BoolVar(&accessLogIncludeHTTPHealthCheckFilter, "healthcheck", false, "Include HTTP Healthcheck accesslog")
	cmd.Flags().BoolVar(&accessLogFollow, "follow", false, "Specify if the logs should be streamed")

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
