// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"bytes"
	"context"
	gojson "encoding/json"
	"fmt"
	"maps"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/k8s"
)

// NoInterruptedConnections checks whether there are no interruptions in
// long-lived E/W LB connections. The test case is used to validate Cilium
// upgrades.
//
// The test case consists of three steps:
//
// 1. Deploying pods and a service which establish the long-lived connections
// (done by "--conn-disrupt-test-setup"). The client pods ("test-conn-disrupt-client")
// establish connections via ClusterIP ("test-conn-disrupt") to server pods
// ("test-conn-disrupt-server"). As there former pods come first before the latter,
// the former pods can crash which increases the pod restart counter. The step
// is responsible for storing the restart counter too.
// 2. Do Cilium upgrade.
// 3. Run the test ("--include-conn-disrupt-test"). The test checks the restart
// counters, and compares them against the previously stored ones. A mismatch
// indicates that a connection was interrupted.
func NoInterruptedConnections() check.Scenario {
	return &noInterruptedConnections{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type noInterruptedConnections struct {
	check.ScenarioBase
}

func (n *noInterruptedConnections) Name() string {
	return "no-interrupted-connections"
}

func (n *noInterruptedConnections) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	restartCount := make(map[string]string)
	// podClients remembers which client a given pod was observed through, so
	// that a restart-count mismatch can be explained by querying the very same
	// pod for the reason its container restarted.
	podClients := make(map[string]*k8s.Client)
	for _, client := range ct.Clients() {
		if ct.Params().IncludeConnDisruptTest {
			pods, err := client.ListPods(ctx, ct.Params().TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + check.KindTestConnDisrupt})
			if err != nil {
				t.Fatalf("Unable to list test-conn-disrupt pods: %s", err)
			}
			if len(pods.Items) == 0 {
				t.Fatal("No test-conn-disrupt-{client,server} pods found")
			}

			for _, pod := range pods.Items {
				restartCount[pod.GetObjectMeta().GetName()] = strconv.Itoa(int(pod.Status.ContainerStatuses[0].RestartCount))
				podClients[pod.GetObjectMeta().GetName()] = client
			}
		}

		if ct.ShouldRunConnDisruptNSTraffic() {
			pods, err := client.ListPods(ctx, ct.Params().TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + check.KindTestConnDisruptNSTraffic})
			if err != nil {
				t.Fatalf("Unable to list test-conn-disrupt-ns-traffic pods: %s", err)
			}
			if len(pods.Items) == 0 {
				t.Fatal("No test-conn-disrupt-{client,server} for NS traffic pods found")
			}

			for _, pod := range pods.Items {
				restartCount[pod.GetObjectMeta().GetName()] = strconv.Itoa(int(pod.Status.ContainerStatuses[0].RestartCount))
				podClients[pod.GetObjectMeta().GetName()] = client
			}
		} else {
			ct.Info("Skipping conn-disrupt-test for NS traffic")
		}

		if ct.ShouldRunConnDisruptL7Traffic() {
			pods, err := client.ListPods(ctx, ct.Params().TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + check.KindTestConnDisruptL7Traffic})
			if err != nil {
				t.Fatalf("Unable to list test-conn-disrupt-l7-traffic pods: %s", err)
			}
			if len(pods.Items) == 0 {
				t.Fatal("No test-conn-disrupt-{client,server} for L7 traffic pods found")
			}

			for _, pod := range pods.Items {
				restartCount[pod.GetObjectMeta().GetName()] = strconv.Itoa(int(pod.Status.ContainerStatuses[0].RestartCount))
				podClients[pod.GetObjectMeta().GetName()] = client
			}
		} else {
			ct.Info("Skipping conn-disrupt-test for L7 traffic")
		}

		if ct.ShouldRunConnDisruptEgressGateway() {
			pods, err := client.ListPods(ctx, ct.Params().TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + check.KindTestConnDisruptEgressGateway})
			if err != nil {
				t.Fatalf("Unable to list test-conn-disrupt-egw pods: %s", err)
			}
			if len(pods.Items) == 0 {
				t.Fatal("No test-conn-disrupt-{client,server} for Egress Gateway pods found")
			}

			for _, pod := range pods.Items {
				restartCount[pod.GetObjectMeta().GetName()] = strconv.Itoa(int(pod.Status.ContainerStatuses[0].RestartCount))
				podClients[pod.GetObjectMeta().GetName()] = client
			}
		} else {
			ct.Info("Skipping conn-disrupt-test for Egress Gateway")
		}
	}

	// Only store restart counters which will be used later when running the same
	// test case, but w/o --conn-disrupt-test-setup.
	if ct.Params().ConnDisruptTestSetup {
		file, err := os.Create(ct.Params().ConnDisruptTestRestartsPath)
		if err != nil {
			t.Fatalf("Failed to create %q file for writing conn disrupt test temp results: %s",
				ct.Params().ConnDisruptTestRestartsPath, err)
		}
		defer file.Close()

		counts := maps.Clone(restartCount)
		j, err := gojson.Marshal(counts)
		if err != nil {
			t.Fatalf("Failed to marshal JSON: %s", err)
		}

		if _, err := file.Write(j); err != nil {
			t.Fatalf("Failed to write conn disrupt test temp result into file: %s", err)
		}

		return
	}

	b, err := os.ReadFile(ct.Params().ConnDisruptTestRestartsPath)
	if err != nil {
		t.Fatalf("Failed to read conn disrupt test result files: %s", err)
	}
	prevRestartCount := make(map[string]string)
	if err := gojson.Unmarshal(b, &prevRestartCount); err != nil {
		t.Fatalf("Failed to unmarshal JSON test result file: %s", err)
	}

	for pod, count := range restartCount {
		if prevCount, found := prevRestartCount[pod]; !found {
			t.Fatalf("Could not find Pod %s restart count", pod)
		} else if prevCount != count {
			t.Fatalf("Pod %s flow was interrupted (restart count does not match %s != %s)%s",
				pod, prevCount, count, restartReason(ctx, ct, podClients[pod], pod))
		}
	}
}

// restartReason returns a human-readable, best-effort explanation of why the
// container of the given conn-disrupt client/server pod restarted. It reports
// the last termination state (exit code, signal, reason), the tail of the
// previous container's logs, and whether Cilium dropped any flow to or from the
// pod during its downtime. It is only used to enrich the failure message so
// that a benign environmental restart (e.g. host CPU saturation starving the
// test client until its socket deadline fires, with the connection never
// dropped) can be told apart from a genuine datapath disruption (a burst of
// DROPPED flows on the pod's IP); it never changes the pass/fail outcome and
// swallows its own errors, returning an empty string when nothing can be
// collected.
func restartReason(ctx context.Context, ct *check.ConnectivityTest, client *k8s.Client, podName string) string {
	if client == nil {
		return ""
	}

	pod, err := client.GetPod(ctx, ct.Params().TestNamespace, podName, metav1.GetOptions{})
	if err != nil || len(pod.Status.ContainerStatuses) == 0 {
		return ""
	}

	cs := pod.Status.ContainerStatuses[0]
	var sb strings.Builder
	if term := cs.LastTerminationState.Terminated; term != nil {
		fmt.Fprintf(&sb, "; last termination: exitCode=%d signal=%d reason=%q message=%q startedAt=%s finishedAt=%s",
			term.ExitCode, term.Signal, term.Reason, term.Message,
			term.StartedAt.Format(time.RFC3339), term.FinishedAt.Format(time.RFC3339))

		// The single most useful benign-vs-real discriminator: did Cilium
		// actually drop any flow to/from this pod while it was down? A clean
		// window (no drops) points at host saturation; a POLICY_DENIED burst
		// points at a real datapath regression.
		if drops := hubbleDropSummary(ctx, ct, pod.Status.PodIP,
			term.StartedAt.Time, term.FinishedAt.Time); drops != "" {
			sb.WriteString(drops)
		}
	}

	var logs bytes.Buffer
	err = client.GetLogs(ctx, pod.Namespace, podName, cs.Name,
		corev1.PodLogOptions{Previous: true, TailLines: ptr.To[int64](20)}, &logs)
	if err == nil {
		if trimmed := strings.TrimSpace(logs.String()); trimmed != "" {
			fmt.Fprintf(&sb, "; previous container logs (tail):\n%s", trimmed)
		}
	}

	return sb.String()
}

// hubbleDropSummary asks Hubble for DROPPED flows involving podIP within the
// pod's downtime window and returns a short summary suitable for appending to
// the failure message. It returns a "0 dropped flows" note when the window was
// clean, a per-reason breakdown when drops are found, and an empty string when
// Hubble is unavailable or the query fails (best-effort, never fatal).
func hubbleDropSummary(ctx context.Context, ct *check.ConnectivityTest, podIP string, since, until time.Time) string {
	hubbleClient := ct.HubbleClient()
	if hubbleClient == nil || podIP == "" || since.IsZero() || until.IsZero() {
		return ""
	}

	// Bound the query so a hung Relay can never stall the failure path.
	queryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Pad the window slightly: container start/finish timestamps and flow
	// timestamps are not perfectly aligned.
	req := &observer.GetFlowsRequest{
		Since: timestamppb.New(since.Add(-5 * time.Second)),
		Until: timestamppb.New(until.Add(5 * time.Second)),
		Whitelist: []*flow.FlowFilter{
			{SourceIp: []string{podIP}, Verdict: []flow.Verdict{flow.Verdict_DROPPED}},
			{DestinationIp: []string{podIP}, Verdict: []flow.Verdict{flow.Verdict_DROPPED}},
		},
	}

	b, err := hubbleClient.GetFlows(queryCtx, req)
	if err != nil {
		return ""
	}

	reasons := make(map[string]int)
	total := 0
	for {
		res, err := b.Recv()
		if err != nil {
			break
		}
		f := res.GetFlow()
		if f == nil {
			continue
		}
		total++
		reason := fmt.Sprintf("%s/%s", f.GetDropReasonDesc(), f.GetTrafficDirection())
		reasons[reason]++
	}

	if total == 0 {
		return fmt.Sprintf("; hubble: 0 dropped flows on %s during downtime (points at benign host saturation, not a datapath drop)", podIP)
	}
	return fmt.Sprintf("; hubble: %d dropped flows on %s during downtime %v (points at a real datapath drop, not benign saturation)", total, podIP, reasons)
}
