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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/isovalent/ipa/system_status/v1alpha"
	ipa_sys "github.com/isovalent/ipa/system_status/v1alpha"
	"github.com/mitchellh/go-wordwrap"
	"github.com/sourcegraph/conc/pool"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/cilium-cli/api"
	"github.com/cilium/cilium/cilium-cli/status"
	"github.com/cilium/cilium/cilium-cli/sysdump"
)

var CmdDiagnostics = &cobra.Command{
	Use:    "diagnostics",
	Short:  "Collect and display diagnostics",
	RunE:   runDiagnostics,
	Hidden: false,
}

func runDiagnostics(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
	defer cancel()
	k8sClient, _ := api.GetK8sClientContextValue(cmd.Context())
	ns := ciliumNamespace(cmd)
	agentPods, err := k8sClient.ListPods(ctx, ns, metav1.ListOptions{LabelSelector: "k8s-app=cilium"})
	if err != nil {
		return fmt.Errorf("failed to list agent pods: %w", err)
	}
	podsIter := func(yield func(*v1.Pod) bool) {
		for i := range agentPods.Items {
			pod := &agentPods.Items[i]
			if pod.Spec.NodeName == "" {
				// Not scheduled yet?
				continue
			}
			if !yield(pod) {
				break
			}
		}
	}

	failingConditions, err := CollectAndPrintDiagnostics(ctx, podsIter, k8sClient, true, os.Stdout)
	if err != nil {
		return err
	}
	if failingConditions {
		os.Exit(1)
	}
	return nil
}

type diagnosticsK8sClient interface {
	ExecInPodWithStderr(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, bytes.Buffer, error)
}

// ANSI codes we use below in addition to the [status.Red] etc.
const (
	ansiClearLine = "\r\033[0K"
	ansiUnderline = "\033[4m"
)

func CollectAndPrintDiagnostics(
	ctx context.Context,
	agentPods iter.Seq[*v1.Pod],
	k8sClient diagnosticsK8sClient,
	interactive bool,
	w io.Writer,
) (hadFailingConditions bool, err error) {
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

	resultsPool := pool.NewWithResults[diagnosticsResult]().
		WithMaxGoroutines(sysdump.DefaultWorkerCount).
		WithContext(ctx)

	for pod := range agentPods {
		if pod.Spec.NodeName == "" {
			// Not scheduled yet?
			continue
		}
		resultsPool.Go(func(ctx context.Context) (diagnosticsResult, error) {
			return fetchDiagnosticsFromPod(ctx, k8sClient, pod), nil
		})
	}

	failedFetches := map[string]error{}
	results, err := resultsPool.Wait()
	if err != nil {
		return false, err
	}
	for _, result := range results {
		if result.err != nil {
			failedFetches[result.nodeName] = result.err
			continue
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
	if interactive {
		fmt.Fprint(w, ansiClearLine)
	}

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
		fmt.Fprintf(w, "=== Alerts ===\n\n")
		for id := range failingConditions {
			meta := metadata[id]
			onNodes := failingConditionsByID[id]
			color := ""
			if interactive {
				color = ansiUnderline
			}
			maxMessageLength := 0
			var maxSeverity ipa_sys.Severity
			for _, onNode := range onNodes {
				maxMessageLength = max(maxMessageLength, len(onNode.condition.Message))
				maxSeverity = max(maxSeverity, onNode.condition.Severity)
			}
			fmt.Fprintf(
				w,
				"%s%s%s [%s]\n",
				color,
				id,
				status.Reset,
				showSeverity(maxSeverity),
			)
			fmt.Fprintf(w, "  Subsystem: %s\n", meta.Subsystem)

			desc := wordwrap.WrapString(meta.Description, 72)
			desc = strings.ReplaceAll(desc, "\n", "\n    ")
			fmt.Fprintf(w, "  Description:\n    %s\n", desc)
			if meta.Resolution != "" {
				reso := wordwrap.WrapString(meta.Resolution, 72)
				reso = strings.ReplaceAll(reso, "\n", "\n    ")
				fmt.Fprintf(w, "  Resolution:\n    %s\n", reso)
			}
			fmt.Fprintf(w, "  Affected nodes (%d/%d):\n",
				len(onNodes),
				len(conditionsPerNode))

			onNewLine := maxMessageLength > 50
			tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			for _, onNode := range onNodes {
				if onNewLine {
					message := wordwrap.WrapString(onNode.condition.Message, 72)
					message = strings.ReplaceAll(message, "\n", "\n      ")
					fmt.Fprintf(
						w,
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
		fmt.Fprintf(w, "=== Fetch failures ===\n\n")
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for name, err := range failedFetches {
			fmt.Fprintf(tw, "%s\t%s\n", name, err)
		}
		tw.Flush()
	}

	fmt.Fprintf(w, "=== Summary ===\n\n")
	color := ""
	if interactive {
		color = status.Green
		if len(failingNodes) > 0 {
			color = status.Red
		}
	}
	var percentNodesHealthy int
	if len(conditionsPerNode) > 0 {
		percentNodesHealthy = 100 * (len(conditionsPerNode) - len(failingNodes)) / len(conditionsPerNode)
	}
	fmt.Fprintf(
		w,
		"Nodes healthy:          %s%d%%\t[%d/%d]\n",
		color,
		percentNodesHealthy,
		len(conditionsPerNode)-len(failingNodes),
		len(conditionsPerNode),
	)
	if interactive {
		fmt.Fprint(w, status.Reset)
	}
	var percentSucceeding int
	if totalSucceedingConditions > 0 {
		percentSucceeding = 100 * (totalSucceedingConditions - totalFailingConditions) / totalSucceedingConditions
	}
	fmt.Fprintf(
		w,
		"Conditions passing:     %s%d%%\t[%d/%d]\n",
		color,
		percentSucceeding,
		totalSucceedingConditions-totalFailingConditions,
		totalSucceedingConditions,
	)
	if interactive {
		fmt.Fprint(w, status.Reset)
	}

	return len(failingConditions) > 0, nil
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

func fetchDiagnosticsFromPod(ctx context.Context, c diagnosticsK8sClient, pod *v1.Pod) (result diagnosticsResult) {
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
