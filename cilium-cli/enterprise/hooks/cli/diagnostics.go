//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/isovalent/ipa/system_status/v1alpha"
	ipa_sys "github.com/isovalent/ipa/system_status/v1alpha"
	"github.com/mitchellh/go-wordwrap"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/workerpool"

	"github.com/cilium/cilium/cilium-cli/api"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/status"
	"github.com/cilium/cilium/cilium-cli/sysdump"
)

var CmdDiagnostics = &cobra.Command{
	Use:    "diagnostics",
	Short:  "Show diagnostics",
	Long:   ``,
	RunE:   runDiagnostics,
	Hidden: true,
}

func runDiagnostics(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
	defer cancel()
	k8sClient, _ := api.GetK8sClientContextValue(cmd.Context())

	agentPods, err := k8sClient.ListPods(ctx, ciliumNamespace(cmd), metav1.ListOptions{LabelSelector: "k8s-app=cilium"})
	if err != nil {
		return fmt.Errorf("failed to list agent pods: %w", err)
	}

	type condPerNode struct {
		updatedAt time.Time
		total     int
		failing   []*ipa_sys.FailingCondition
	}

	type nodeInfo struct {
		system    *ipa_sys.SystemID
		startedAt time.Time
	}

	nodeInfos := map[string]nodeInfo{}
	metadata := map[string]*ipa_sys.ConditionMetadata{}
	conditionsPerNode := map[string]condPerNode{}

	pool := workerpool.New(sysdump.DefaultWorkerCount)
	results := make(chan diagnosticsResult, 1)
	for i := range agentPods.Items {
		pod := &agentPods.Items[i]
		if pod.Spec.NodeName == "" {
			// Not scheduled yet?
			continue
		}
		pool.Submit(fmt.Sprintf("%d", i), func(ctx context.Context) error {
			results <- fetchDiagnosticsFromPod(ctx, k8sClient, pod)
			return nil
		})
	}

	failedFetches := map[string]error{}
	nodeCount := 0
	for result := range results {
		if result.err != nil {
			failedFetches[result.nodeName] = result.err
			continue
		}
		fmt.Printf("\033[0KFetching diagnostics (%d/%d)...\r",
			result.nodeName, nodeCount+1, len(agentPods.Items))

		nodeCount++
		if nodeCount == len(agentPods.Items) {
			close(results)
			break
		}
		if result.metadata != nil {
			for _, m := range result.metadata.Conditions {
				metadata[m.ConditionId] = m
			}
		}
		nodeInfos[result.nodeName] = nodeInfo{
			system:    result.update.System,
			startedAt: result.update.StartedAt.AsTime(),
		}
		conditionsPerNode[result.nodeName] = condPerNode{
			updatedAt: result.updatedAt,
			total:     int(result.update.TotalConditions),
			failing:   result.update.FailingConditions,
		}
	}
	pool.Close()
	fmt.Print("\r\033[0K")

	type conditionOnNode struct {
		node      string
		updatedAt time.Time
		condition *ipa_sys.FailingCondition
	}
	failingConditionsByID := map[string][]conditionOnNode{}
	failingConditions := sets.New[string]()
	failingNodes := sets.New[string]()
	totalSucceedingConditions, totalFailingConditions := 0, 0
	for name, conditions := range conditionsPerNode {
		totalSucceedingConditions += conditions.total
		for _, cond := range conditions.failing {
			failingConditionsByID[cond.ConditionId] = append(failingConditionsByID[cond.ConditionId], conditionOnNode{name, conditions.updatedAt, cond})
			failingConditions.Insert(cond.ConditionId)
			failingNodes.Insert(name)
			totalFailingConditions++
		}
	}

	if len(failingConditions) > 0 {
		fmt.Printf("=== Alerts ===\n\n")
		for id := range failingConditions {
			meta := metadata[id]
			onNodes := failingConditionsByID[id]

			maxMessageLength := 0
			var maxSeverity ipa_sys.Severity
			for _, onNode := range onNodes {
				maxMessageLength = max(maxMessageLength, len(onNode.condition.Message))
				maxSeverity = max(maxSeverity, onNode.condition.Severity)
			}

			fmt.Printf(
				"\033[4m%s%s [%s]\n",
				id,
				status.Reset,
				showSeverity(maxSeverity),
			)
			fmt.Printf("  Subsystem: %s\n", meta.Subsystem)

			desc := wordwrap.WrapString(meta.Description, 72)
			desc = strings.ReplaceAll(desc, "\n", "\n    ")
			fmt.Printf("  Description:\n    %s\n", desc)
			if meta.Resolution != "" {
				reso := wordwrap.WrapString(meta.Resolution, 72)
				reso = strings.ReplaceAll(reso, "\n", "\n    ")
				fmt.Printf("  Resolution:\n    %s\n", reso)
			}
			fmt.Printf("  Affected nodes (%d/%d):\n",
				len(onNodes),
				len(conditionsPerNode))

			onNewLine := maxMessageLength > 50
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			for _, onNode := range onNodes {
				if onNewLine {
					message := wordwrap.WrapString(onNode.condition.Message, 72)
					message = strings.ReplaceAll(message, "\n", "\n      ")
					fmt.Printf(
						"    %s (%s ago):\n      %s\n",
						onNode.node,
						time.Since(onNode.updatedAt).Truncate(time.Second),
						message,
					)
				} else {
					fmt.Fprintf(tw,
						"    %s (%s ago):\t%s\n",
						onNode.node,
						time.Since(onNode.updatedAt).Truncate(time.Second),
						onNode.condition.Message,
					)
				}
			}
			tw.Flush()
		}
		fmt.Println()
	}

	if len(failedFetches) > 0 {
		fmt.Printf("=== Fetch failures ===\n\n")
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for name, err := range failedFetches {
			fmt.Fprintf(tw, "%s\t%s\n", name, err)
		}
		tw.Flush()
	}

	fmt.Printf("=== Summary ===\n\n")
	var color = status.Green
	if len(failingNodes) > 0 {
		color = status.Red
	}
	fmt.Printf(
		"Nodes healthy:          %s%d%%\t[%d/%d]%s\n",
		color,
		100*(len(conditionsPerNode)-len(failingNodes))/len(conditionsPerNode),
		len(conditionsPerNode)-len(failingNodes),
		len(conditionsPerNode),
		status.Reset,
	)
	fmt.Printf(
		"Conditions passing:     %s%d%%\t[%d/%d]%s\n",
		color,
		100*(totalSucceedingConditions-totalFailingConditions)/totalSucceedingConditions,
		totalSucceedingConditions-totalFailingConditions,
		totalSucceedingConditions,
		status.Reset,
	)

	return nil
}

func showSeverity(severity ipa_sys.Severity) string {
	switch severity {
	case v1alpha.Severity_SEVERITY_CRITICAL:
		return status.Red + "CRITICAL" + status.Reset
	case v1alpha.Severity_SEVERITY_DEBUG:
		return status.Blue + "DEBUG" + status.Reset
	case v1alpha.Severity_SEVERITY_MAJOR:
		return status.Red + "MAJOR" + status.Reset
	case v1alpha.Severity_SEVERITY_MINOR:
		return status.Magenta + "MINOR" + status.Reset
	case v1alpha.Severity_SEVERITY_UNSPECIFIED:
		return "?"
	}
	panic(fmt.Sprintf("unexpected v1alpha.Severity: %#v", severity))
}

var diagnosticsCommand = []string{
	"cilium-dbg",
	"shell",
	"--",
	"diagnostics/export",
}

type diagnosticsResult struct {
	nodeName  string
	metadata  *ipa_sys.SystemMetadataUpdate
	update    *ipa_sys.SystemStatusUpdate
	updatedAt time.Time
	err       error
}

func fetchDiagnosticsFromPod(ctx context.Context, c *k8s.Client, pod *v1.Pod) (result diagnosticsResult) {
	result.nodeName = pod.Spec.NodeName
	output, errOutput, err := c.ExecInPodWithStderr(ctx, pod.Namespace, pod.Name, "cilium-agent", diagnosticsCommand)
	if err != nil {
		var errStr string
		if errOutput.String() != "" {
			errStr = strings.TrimSpace(errOutput.String())
		} else {
			errStr = err.Error()
		}
		result.err = fmt.Errorf("failed to fetch diagnostics from %s: (%s)", pod.Name, errStr)
		return
	}
	dec := json.NewDecoder(&output)

	for {
		var event struct {
			SystemStatus *ipa_sys.SystemStatusEvent `json:"system_status"`
			Time         time.Time                  `json:"time"`
		}
		if err := dec.Decode(&event); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			result.err = fmt.Errorf("json decode failed: %w", err)
			return
		}

		if meta := event.SystemStatus.GetMetadata(); meta != nil {
			result.metadata = meta
		} else if upd := event.SystemStatus.GetStatus(); upd != nil {
			result.update = upd
			result.updatedAt = event.Time
		}
	}
	return
}
