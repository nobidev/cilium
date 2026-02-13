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
	applicationLogConnectionIDsFilter []string
	applicationLogPodNameFilter       string
	applicationLogFollow              bool
	applicationLogFiles               []string
)

func newCmdLoadbalancerT2ApplicationlogStreamer() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "applicationlog",
		Short: "Display Loadbalancer T2 application log",
		Long:  "",
		RunE: func(c *cobra.Command, _ []string) error {
			var readers []reader
			var err error
			errGrp, ctx := errgroup.WithContext(c.Context())

			if len(applicationLogFiles) == 0 {
				readers, err = podReaders(ctx, ciliumNamespace(c), "name=cilium-envoy", applicationLogPodNameFilter, applicationLogFollow, nil)
			} else {
				readers, err = fileReaders(applicationLogFiles)
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

						if strings.Contains(logLine, "][access]") {
							continue
						}

						if includeApplicationlogLine(logLine) {
							if _, err = io.Copy(os.Stdout, strings.NewReader(fmt.Sprintf("[%s] %s\n", r.name, logLine))); err != nil {
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

	cmd.Flags().StringSliceVar(&applicationLogFiles, "files", nil, "Comma-separated list of application log files. If empty, logs will be retrieved from ILB Envoy pods")
	cmd.Flags().StringSliceVar(&applicationLogConnectionIDsFilter, "connection-ids", []string{}, "List of connection ids to filter the application log for")
	cmd.Flags().StringVar(&applicationLogPodNameFilter, "pod", "", "Filter the application log for a given Envoy Pod Name")

	cmd.Flags().BoolVar(&applicationLogFollow, "follow", false, "Specify if the logs should be streamed")

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
