//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import (
	"context"
	"fmt"
	"regexp"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	enterpriseDefaults "github.com/cilium/cilium/cilium-cli/enterprise/defaults"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

// ExternalCiliumDNSProxy returns the scenario for the tests related to the external cilium-dnsproxy component.
func ExternalCiliumDNSProxy(pods map[string]check.Pod) check.Scenario {
	return &externalCiliumDNSProxy{
		ScenarioBase:       check.NewScenarioBase(),
		ciliumDNSProxyPods: pods,
	}
}

// externalCiliumDNSProxy holds needed dependencies for the tests.
type externalCiliumDNSProxy struct {
	check.ScenarioBase
	ciliumDNSProxyPods map[string]check.Pod
}

// Name returns the name of the scenario.
func (s *externalCiliumDNSProxy) Name() string {
	return "external-cilium-dns-proxy"
}

// Run implements the scenario to test external cilium-dnsproxy component.
func (s *externalCiliumDNSProxy) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	for _, client := range ct.ClientPods() {
		// Perform a nslookup on each service name using the cluster's default DNS server.
		//
		// This emulates the DNS behavior we expect to see in a real cluster, but doesn't allow us to control
		// the DNS server address being used in the lookup (which often is single-stack even for dual-stack-enabled clusters).
		for _, svc := range ct.EchoServices() {
			t.NewAction(s, "nslookup-svc-at-clusterdns", &client, svc, features.IPFamilyAny).Run(func(a *check.Action) {
				// Iterate enough time to observe the metric evolves, nslookup command will
				// hit the cilium-dnsproxy pods, note that the iteration is done directly in
				// the pod for performance concerns.
				cmd := fmt.Sprintf("for i in `seq 0 25`; do nslookup %s; done", svc.NameWithoutNamespace())
				a.ExecInPod(ctx, []string{"/bin/sh", "-c", cmd})

				// Retrieve the cilium-dnsproxy pod on the same node as the client.
				dnsProxy, err := retrievePodOnNode(s.ciliumDNSProxyPods, client.NodeName())
				if err != nil {
					a.Fatalf("failed to test external cilium-dnsproxy pod: %s", err)
				}

				a.ValidateMetrics(ctx, dnsProxy, a.GetEgressMetricsRequirements())
			})
		}

		// Perform a nslookup using the dns-test-server container of each echo pod as the DNS server.
		//
		// This is not a setup we expect to common in the real world, but it allows us to control the IP address
		// (and therefore IP family) of the DNS server precisely.
		for _, pod := range ct.EchoPods() {
			// We are using the pod IP rather than the service IP because there is no service on the echo pods targeting
			// port 53.
			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				t.NewAction(s, "nslookup-localhost-at-echopod", &client, pod, ipFam).Run(func(a *check.Action) {
					// A DNS lookup on "localhost" is the only hostname for which the echo pods are able to respond,
					// as the "local" plugin is the only responder configured. See https://coredns.io/plugins/local/
					cmd := fmt.Sprintf("for i in `seq 0 25`; do nslookup localhost %s; done", pod.Address(ipFam))
					a.ExecInPod(ctx, []string{"/bin/sh", "-c", cmd})

					// Retrieve the cilium-dnsproxy pod on the same node as the client.
					dnsProxy, err := retrievePodOnNode(s.ciliumDNSProxyPods, client.NodeName())
					if err != nil {
						a.Fatalf("failed to test external cilium-dnsproxy pod: %s", err)
					}

					a.ValidateMetrics(ctx, dnsProxy, a.GetEgressMetricsRequirements())
				})
			})
		}
	}

}

// retrievePodOnNode returns a pod belonging to the given node.
func retrievePodOnNode(pods map[string]check.Pod, node string) (check.Pod, error) {
	for _, pod := range pods {
		if node == pod.NodeName() {
			return pod, nil
		}
	}

	return check.Pod{}, fmt.Errorf("no pod found on node %s", node)
}

// regexpContainerArgPrometheusPort is the container argument holding the prometheus port.
var regexpContainerArgPrometheusPort = regexp.MustCompile("^--prometheus-port=([0-9]+)$")

// ExternalCiliumDNSProxySource returns the MetricsSource for the cilium-dnsproxy component.
func ExternalCiliumDNSProxySource(dnsProxyPods map[string]check.Pod) check.MetricsSource {
	if len(dnsProxyPods) == 0 {
		// Early exit if there are no Cilium DNS Proxy pods.
		return check.MetricsSource{}
	}

	source := check.MetricsSource{
		Name: enterpriseDefaults.ExternalCiliumDNSProxyName,
	}

	// Retrieve the port value for Prometheus.
	// There is no container init, but we can retrieve it from
	// container args `--prometheus-port=9967`.
	for _, p := range dnsProxyPods {
		source.Pods = append(source.Pods, p)
		// parse all the containers and retrieve the port
		if source.Port == "" {
			if port := retrievePort(p.Pod.Spec.Containers); port != "" {
				source.Port = port
			}
		}
	}

	// Prometheus port was not find, let's return an empty MetricsSource.
	if source.Port == "" {
		return check.MetricsSource{}
	}

	return source
}

func retrievePort(containers []v1.Container) string {
	for _, c := range containers {
		if c.Name == enterpriseDefaults.ExternalCiliumDNSProxyName {
			// extract the port from the arguments
			if port := extractPort(c.Args); port != "" {
				return port
			}
		}
	}
	return ""
}

// extractPort from the arguments from cilium-dnsproxy pods.
func extractPort(args []string) string {
	for _, arg := range args {
		if regexpContainerArgPrometheusPort.MatchString(arg) {
			s := regexpContainerArgPrometheusPort.FindStringSubmatch(arg)
			// retrieve only the port which is first group to match
			return s[1]
		}
	}

	return ""
}

// RetrieveExternalCiliumDNSProxyPods fetches the Cilium DNS Proxy pods information from all clients.
func RetrieveExternalCiliumDNSProxyPods(ctx context.Context, ct *check.ConnectivityTest) (map[string]check.Pod, error) {
	externalCiliumDNSProxyPods := make(map[string]check.Pod)
	for _, client := range ct.Clients() {
		// cilium-dnsproxy pods are labelled with `k8s-app=cilium-dnsproxy`, let's filter on it.
		ciliumDNSProxyLabelSelector := fmt.Sprintf("k8s-app=%s", enterpriseDefaults.ExternalCiliumDNSProxyName)
		pods, err := client.ListPods(ctx, ct.Params().CiliumNamespace, metav1.ListOptions{LabelSelector: ciliumDNSProxyLabelSelector})
		if err != nil {
			return nil, fmt.Errorf("unable to list %s pods: %w", enterpriseDefaults.ExternalCiliumDNSProxyName, err)
		}

		// Retrieve all the pods and return them.
		for _, pod := range pods.Items {
			externalCiliumDNSProxyPods[pod.Name] = check.Pod{
				K8sClient: client,
				Pod:       pod.DeepCopy(),
			}
		}
	}

	return externalCiliumDNSProxyPods, nil
}
