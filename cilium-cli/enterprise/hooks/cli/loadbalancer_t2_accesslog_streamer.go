// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

const (
	errSinceCannotUseFiles = "--since cannot be used with --files"
	errSinceInvalidValue   = "invalid --since value"
	errSincePositive       = "--since must be a positive duration"
	errNoLoggerPods        = "no namespace-logger pods found in namespace"
)

var (
	accessLogRequestIdFilter              string
	accessLogVIPAndPortFilter             string
	accessLogGenericFilters               []string
	accessLogApplicationTypesFilter       []string
	accessLogIncludeHTTPHealthCheckFilter bool
	accessLogFollow                       bool
	accessLogFiles                        []string
	accessLogTenant                       string
	accessLogSince                        string
)

func newCmdLoadbalancerT2AccesslogStreamer() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "accesslog",
		Short: "Display Loadbalancer T2 access log",
		Long:  "",
		RunE: func(c *cobra.Command, _ []string) error {
			if accessLogSince != "" && len(accessLogFiles) != 0 {
				return errors.New(errSinceCannotUseFiles)
			}

			var readers []reader
			var err error
			var sinceSeconds *int64
			errGrp, ctx := errgroup.WithContext(c.Context())

			if accessLogSince != "" {
				d, parseErr := time.ParseDuration(accessLogSince)
				if parseErr != nil {
					return fmt.Errorf("%s %q: %w", errSinceInvalidValue, accessLogSince, parseErr)
				}
				if d <= 0 {
					return fmt.Errorf("%s, got %q", errSincePositive, accessLogSince)
				}
				s := int64(d.Seconds())
				sinceSeconds = &s
			}

			if accessLogTenant != "" {
				readers, err = podReaders(ctx, accessLogTenant, "app=namespace-logger", "", accessLogFollow, sinceSeconds)
			} else if len(accessLogFiles) == 0 {
				readers, err = podReaders(ctx, ciliumNamespace(c), "name=cilium-envoy", "", accessLogFollow, sinceSeconds)
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

			if accessLogTenant != "" && len(readers) == 0 {
				return fmt.Errorf("%s %q", errNoLoggerPods, accessLogTenant)
			}

			for _, r := range readers {
				errGrp.Go(func() error {
					scanner := bufio.NewScanner(r.r)
					for scanner.Scan() {
						logLine := scanner.Text()

						if accessLogTenant != "" {
							if !includeTenantLogLine(logLine) {
								continue
							}
						} else {
							if !includeAccesslogLine(logLine) {
								continue
							}
						}

						if _, err := io.Copy(os.Stdout, strings.NewReader(fmt.Sprintf("[%s] %s\n", r.name, logLine))); err != nil {
							return fmt.Errorf("failed to copy: %w", err)
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
	cmd.Flags().StringSliceVar(&accessLogApplicationTypesFilter, "application-types", []string{"udp", "tcp", "tls_passthrough", "tls", "https", "http"}, "Filter for the provided application types")
	cmd.Flags().BoolVar(&accessLogIncludeHTTPHealthCheckFilter, "healthcheck", false, "Include HTTP Healthcheck accesslog")
	cmd.Flags().BoolVar(&accessLogFollow, "follow", false, "Specify if the logs should be streamed")
	cmd.Flags().StringVar(&accessLogTenant, "tenant", "", "Tenant namespace to read access logs from namespace-logger pods")
	cmd.Flags().StringVar(&accessLogSince, "since", "", "Show tenant logs since duration (e.g. 24h, 30m, 1h30m) (requires --tenant)")

	return cmd
}

func includeAccesslogLine(logLine string) bool {
	if !strings.Contains(logLine, "][access]") {
		return false
	}

	// filter for log application type (OR)
	logApplicationTypes := []string{}

	logApplicationTypes = append(logApplicationTypes, accessLogApplicationTypesFilter...)

	if accessLogIncludeHTTPHealthCheckFilter {
		logApplicationTypes = append(logApplicationTypes, "healthcheck")
	}

	matchesOneLogApplicationType := false
	for _, lt := range logApplicationTypes {
		if strings.Contains(logLine, fmt.Sprintf("][access][%s]", lt)) {
			matchesOneLogApplicationType = true
		}
	}

	if len(logApplicationTypes) > 0 && !matchesOneLogApplicationType {
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

func includeTenantLogLine(logLine string) bool {
	for _, f := range accessLogGenericFilters {
		if !strings.Contains(logLine, f) {
			return false
		}
	}
	return true
}
