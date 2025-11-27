// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package privnet

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"slices"
	"strings"
	"text/template"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer/yaml"
	k8stypes "k8s.io/apimachinery/pkg/types"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	enterpriseK8s "github.com/cilium/cilium/cilium-cli/enterprise/hooks/k8s"
	"github.com/cilium/cilium/cilium-cli/enterprise/hooks/utils"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	//go:embed manifests/privatenetwork.yaml
	privateNetworkTemplate string

	//go:embed manifests/vm-client.yaml
	vmClientTemplate string

	//go:embed manifests/vm-echo.yaml
	vmEchoTemplate string

	//go:embed manifests/vm-echo-script.py
	vmEchoScript string

	//go:embed manifests/external-endpoint-policy.yaml
	externalEndpointPolicyTemplate string
)

const (
	NetworkA = "network-a"
	NetworkB = "network-b"
	NetworkC = "network-c"
	NetworkD = "network-d"

	EchoServerPort = 8000
)

type NodeName string

type TestRun struct {
	params     Params
	client     *enterpriseK8s.EnterpriseClient
	inbClients []*enterpriseK8s.EnterpriseClient
	log        *slog.Logger

	families       []features.IPFamily
	webhookEnabled bool
	webhookPlanID  k8stypes.UID

	ciliumPodsCluster map[NodeName]check.Pod
	ciliumPodsINBs    map[NodeName]check.Pod

	vms map[NetworkName]map[VMName]VM
	ext map[NetworkName]map[VMName]VM

	pod map[VMName]*corev1.Pod

	policies map[string]k8s.Object

	cancel context.CancelFunc
	failed bool
}

func NewTestRun(
	ctx context.Context,
	cancel context.CancelFunc,
	params Params,
	client *enterpriseK8s.EnterpriseClient,
	inbClients []*enterpriseK8s.EnterpriseClient,
) *TestRun {
	level := slog.LevelInfo
	if params.Debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))

	return &TestRun{
		params:     params,
		client:     client,
		inbClients: inbClients,
		log:        log,
		vms:        map[NetworkName]map[VMName]VM{},
		ext:        map[NetworkName]map[VMName]VM{},
		pod:        map[VMName]*corev1.Pod{},
		policies:   map[string]k8s.Object{},
		cancel:     cancel,
		failed:     false,
	}
}

func objectFromYAML(yamlStr string) (*unstructured.Unstructured, error) {
	decoder := yamlutil.NewYAMLOrJSONDecoder(strings.NewReader(yamlStr), 100)

	var rawObj k8sruntime.RawExtension
	if err := decoder.Decode(&rawObj); err != nil {
		return nil, fmt.Errorf("failed decoding YAML: %w", err)
	}
	obj, _, err := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme).Decode(rawObj.Raw, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed deserializing YAML: %w", err)
	}
	unstructuredMap, err := k8sruntime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, fmt.Errorf("failed converting YAML to unstructured object: %w", err)
	}

	return &unstructured.Unstructured{Object: unstructuredMap}, nil
}

// toK8sObjects converts a slice of specific k8s objects to a slice of generic k8s objects.
func toK8sObjects[T k8s.Object](objs []T) []k8s.Object {
	ret := make([]k8s.Object, 0, len(objs))
	for _, obj := range objs {
		ret = append(ret, obj)
	}
	return ret
}

// updateNetworkMap updates the target network map with the provided VMs,
// ensuring that inner maps are created as needed.
func updateNetworkMap(target map[NetworkName]map[VMName]VM, vms []VM) {
	for _, vm := range vms {
		inner := target[vm.NetName]
		if inner == nil {
			inner = make(map[VMName]VM)
			target[vm.NetName] = inner
		}
		inner[vm.Name] = vm
	}
}

func (t *TestRun) retrieveCiliumConfig(ctx context.Context) error {
	cm, err := t.client.GetConfigMap(ctx, t.params.CiliumNamespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}

	if cm.Data["enable-ipv4"] == "true" {
		t.families = append(t.families, features.IPFamilyV4)
	}

	if cm.Data["enable-ipv6"] == "true" {
		t.families = append(t.families, features.IPFamilyV6)
	}

	if cm.Data["private-networks-webhook-enabled"] == "true" {
		t.webhookEnabled = true
	}

	return nil
}

func (t *TestRun) retrieveMTVConfig(ctx context.Context) error {
	if !t.webhookEnabled {
		return nil
	}
	plan := &unstructured.Unstructured{}
	plan.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "forklift.konveyor.io",
		Version: "v1beta1",
		Kind:    "Plan",
	})
	plan, err := t.client.GetGeneric(ctx, t.params.TestNamespace, t.params.ForkliftPlanName, plan)
	if err != nil {
		return err
	}

	t.webhookPlanID = plan.GetUID()
	return nil
}

func (t *TestRun) retrieveCiliumPods(ctx context.Context) error {
	list := func(client *k8s.Client) (iter.Seq2[NodeName, check.Pod], error) {
		pods, err := client.ListPods(ctx, t.params.CiliumNamespace, metav1.ListOptions{LabelSelector: t.params.AgentPodSelector})
		if err != nil {
			return nil, fmt.Errorf("listing pods: %w", err)
		}

		if len(pods.Items) == 0 {
			return nil, fmt.Errorf("no pod found in namespace %s matching selector %q", t.params.CiliumNamespace, t.params.AgentPodSelector)
		}

		return func(yield func(NodeName, check.Pod) bool) {
			for _, pod := range pods.Items {
				if !yield(NodeName(pod.Spec.NodeName), check.Pod{K8sClient: client, Pod: &pod}) {
					return
				}
			}
		}, nil
	}

	got, err := list(t.client.Client)
	if err != nil {
		return fmt.Errorf("retrieving Cilium pods in %s: %w", t.client.ClusterName(), err)
	}
	t.ciliumPodsCluster = maps.Collect(got)

	t.ciliumPodsINBs = make(map[NodeName]check.Pod)
	for _, client := range t.inbClients {
		got, err := list(client.Client)
		if err != nil {
			return fmt.Errorf("retrieving Cilium pods in %s: %w", client.ClusterName(), err)
		}
		maps.Insert(t.ciliumPodsINBs, got)
	}

	return nil
}

func (t *TestRun) createNamespace(ctx context.Context, client *enterpriseK8s.EnterpriseClient) error {
	_, err := client.GetNamespace(ctx, t.params.TestNamespace, metav1.GetOptions{})
	if err != nil {
		t.log.Info(fmt.Sprintf("📜 Creating namespace %s in cluster %s", t.params.TestNamespace, client.ClusterName()))
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: t.params.TestNamespace,
			},
		}
		_, err = client.CreateNamespace(ctx, namespace, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed creating namespace %s in cluster %s: %w", t.params.TestNamespace, client.ClusterName(), err)
		}
	} else {
		t.log.Info(fmt.Sprintf("📜 Namespace %s already exists in cluster %s", t.params.TestNamespace, client.ClusterName()))
	}
	return nil
}

func (t *TestRun) renderNetworkPolicies(epName string, dstPort int) ([]k8s.Object, error) {
	data := struct {
		Name          string
		TestNamespace string
		Port          int
	}{
		Name:          epName,
		TestNamespace: t.params.TestNamespace,
		Port:          dstPort,
	}
	policyYaml, err := renderTemplate(externalEndpointPolicyTemplate, data)
	if err != nil {
		return nil, fmt.Errorf("failed to render IsovalentNetworkPolicy template: %w", err)
	}
	policyObjs, err := utils.ParseYAML[*isovalentv1alpha1.IsovalentNetworkPolicy](policyYaml)
	if err != nil || len(policyObjs) == 0 {
		return nil, fmt.Errorf("failed to deserializing manifest for IsovalentNetworkPolicy: %w", err)
	}

	return toK8sObjects(policyObjs), nil
}

type networkTemplateData struct {
	Network         NetworkName
	Prefixes        []string
	INBClusterNames []string
	INBInterface    string
	Routes          []Route
}

func (t *TestRun) renderClusterNetworkTopology(network NetworkName, ndata NetworkData) ([]k8s.Object, error) {
	data := networkTemplateData{
		Network:  network,
		Prefixes: ndata.Prefixes,
		Routes:   ndata.Routes,
	}

	for _, inb := range ndata.INBs {
		data.INBClusterNames = append(data.INBClusterNames, inb.ClusterName)
	}

	networkYAML, err := renderTemplate(privateNetworkTemplate, data)
	if err != nil {
		return nil, fmt.Errorf("failed rendering template for network %s: %w", network, err)
	}
	networkObjs, err := utils.ParseYAML[*isovalentv1alpha1.ClusterwidePrivateNetwork](networkYAML)
	if err != nil || len(networkObjs) == 0 {
		return nil, fmt.Errorf("failed deserializing manifest for network %s: %w", network, err)
	}

	objs := toK8sObjects(networkObjs)
	for _, vm := range ndata.VMs {
		var tmpl string
		switch vm.Kind {
		case VMKindClient:
			tmpl = vmClientTemplate
		case VMKindEcho:
			tmpl = vmEchoTemplate
		default:
			return nil, fmt.Errorf("unknown VM kind %s", vm.Kind)
		}

		type vmData struct {
			VM
			TestNamespace   string
			VMImage         string
			Script          string
			ServePort       int
			NeedsAnnotation bool
			PlanID          k8stypes.UID
		}
		data := vmData{
			VM:              vm,
			TestNamespace:   t.params.TestNamespace,
			VMImage:         t.params.VMImage,
			Script:          vmEchoScript,
			ServePort:       EchoServerPort,
			NeedsAnnotation: !t.webhookEnabled || vm.ID == "",
			PlanID:          t.webhookPlanID,
		}
		vmYAML, err := renderTemplate(tmpl, data)
		if err != nil {
			return nil, fmt.Errorf("failed rendering template for VM %s: %w", vm.Name, err)
		}
		vmObj, err := objectFromYAML(vmYAML)
		if err != nil {
			return nil, fmt.Errorf("failed deserializing manifest for VM %s: %w", vm.Name, err)
		}

		objs = append(objs, vmObj)
	}

	return objs, nil
}

func (t *TestRun) applyINBNetworkTopology(ctx context.Context, network NetworkName, ndata NetworkData) error {
	for _, inb := range ndata.INBs {
		data := networkTemplateData{
			Network:      network,
			Prefixes:     ndata.Prefixes,
			INBInterface: inb.Interface,
			Routes:       ndata.Routes,
		}

		networkYAML, err := renderTemplate(privateNetworkTemplate, data)
		if err != nil {
			return fmt.Errorf("failed rendering template for network %s: %w", network, err)
		}
		networkObjs, err := utils.ParseYAML[*isovalentv1alpha1.ClusterwidePrivateNetwork](networkYAML)
		if err != nil || len(networkObjs) == 0 {
			return fmt.Errorf("failed deserializing manifest for network %s: %w", network, err)
		}

		objs := toK8sObjects(networkObjs)
		for _, client := range t.inbClients {
			if client.ClusterName() == "kind-"+inb.ClusterName {
				if err := t.applyObjs(ctx, client, objs); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (t *TestRun) waitForVMToBeReady(ctx context.Context, namespace, name string) error {
	ctx, cancel := context.WithTimeout(ctx, check.LongTimeout)
	defer cancel()

	t.log.Info(fmt.Sprintf("⌛ Waiting for VM %s to become ready", name))

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	var lastErrMsg string
	for {
		err := t.client.ExecInVMWithWriters(ctx, namespace, name, []string{"hostname"}, stdout, stderr)
		if err == nil {
			break
		}

		if err.Error() != lastErrMsg {
			t.log.Debug("VM exec failed",
				logfields.Name, name,
				logfields.Error, err,
				logfields.Stdout, stdout,
				logfields.Stderr, stderr,
			)
		}
		lastErrMsg = err.Error()

		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for VM to become ready: %w", err)
		case <-time.After(check.PollInterval):
		}
	}

	hostname := strings.TrimSpace(stdout.String())
	if hostname != name {
		return fmt.Errorf("unexpected hostname. want %q, got %q", name, hostname)
	}
	return nil
}

func (t *TestRun) retrieveExternalVMs(ctx context.Context, client *enterpriseK8s.EnterpriseClient) ([]VM, error) {
	imes, err := client.EnterpriseCiliumClientset.IsovalentV1alpha1().
		PrivateNetworkExternalEndpoints(t.params.TestNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing PrivateNetworkExternalEndpoints: %w", err)
	}

	vms := make([]VM, len(imes.Items))
	for i, ime := range imes.Items {
		addrs := ime.Spec.Interface.Addressing
		var ip4, ip6 netip.Addr
		var err error

		if addrs.IPv4 != "" {
			ip4, err = netip.ParseAddr(addrs.IPv4)
			if err != nil {
				return nil, fmt.Errorf("parsing IP address %q: %w", addrs.IPv4, err)
			}
		}

		if addrs.IPv6 != "" {
			ip6, err = netip.ParseAddr(addrs.IPv6)
			if err != nil {
				return nil, fmt.Errorf("parsing IP address %q: %w", addrs.IPv6, err)
			}
		}

		vms[i] = VM{
			Name:    VMName(ime.GetName()),
			NetName: NetworkName(ime.Spec.Interface.Network),
			NetIPv4: ip4,
			NetIPv6: ip6,
			NetMAC:  ime.Spec.Interface.MAC,
			Kind:    VMKindExtern,
		}
	}
	return vms, nil
}

func (t *TestRun) VM(network NetworkName, vmName VMName) VM {
	return t.vms[network][vmName]
}

func (t *TestRun) External(network NetworkName) iter.Seq[VM] {
	return maps.Values(t.ext[network])
}

func (t *TestRun) VirtLauncherPodForVM(vm VM) *corev1.Pod {
	return t.pod[vm.Name]
}

func (t *TestRun) SetupAndValidate(ctx context.Context) error {
	if err := t.retrieveCiliumConfig(ctx); err != nil {
		return fmt.Errorf("failed retrieving Cilium configuration: %w", err)
	}
	if err := t.retrieveMTVConfig(ctx); err != nil {
		return fmt.Errorf("failed retrieving MTV configuration: %w", err)
	}
	if err := t.retrieveCiliumPods(ctx); err != nil {
		return fmt.Errorf("failed retrieving Cilium pods: %w", err)
	}

	if err := t.createNamespace(ctx, t.client); err != nil {
		return err
	}

	toApply := []k8s.Object{}
	for network, networkData := range networkTopology {
		objs, err := t.renderClusterNetworkTopology(network, networkData)
		if err != nil {
			return err
		}
		toApply = slices.Concat(toApply, objs)
		updateNetworkMap(t.vms, networkData.VMs)
	}

	if err := t.applyObjs(ctx, t.client, toApply); err != nil {
		return err
	}

	for _, vms := range t.vms {
		for vmName := range vms {
			err := t.waitForVMToBeReady(ctx, t.params.TestNamespace, vmName.String())
			if err != nil {
				return fmt.Errorf("failed waiting for VM %s to become ready: %w", vmName, err)
			}

			t.pod[vmName], err = t.client.FindLauncherPodForVM(ctx, t.params.TestNamespace, vmName.String())
			if err != nil {
				return err
			}
		}
	}

	for _, client := range t.inbClients {
		if err := t.createNamespace(ctx, client); err != nil {
			return err
		}

		vms, err := t.retrieveExternalVMs(ctx, client)
		if err != nil {
			return fmt.Errorf("failed retrieving external VMs from cluster %s: %w", client.ClusterName(), err)
		}
		updateNetworkMap(t.ext, vms)
	}

	// update network definitions in inb clients
	for network, networkData := range networkTopology {
		err := t.applyINBNetworkTopology(ctx, network, networkData)
		if err != nil {
			return err
		}
	}

	if len(t.inbClients) > 0 && len(t.ext) == 0 {
		return errors.New("INB clients specified, but no external VM found")
	}

	return nil
}

func (t *TestRun) Run(
	ctx context.Context,
	scenario Scenario,
	expectations Expectation,
	overrideIPFamilies ...features.IPFamily,
) {
	if err := ctx.Err(); err != nil {
		// context done or cancelled due to previous scenario failure
		return
	}

	scenario.Run(ctx, expectations, overrideIPFamilies...)
	if scenario.Failed() && t.cancel != nil {
		t.log.Error(fmt.Sprintf("Scenario %s failed", scenario.Name()))
		t.cancel()
		t.cancel = nil
		t.failed = true
	}
}

func (t *TestRun) Failed() bool {
	return t.failed
}

func (t *TestRun) Cleanup(ctx context.Context) {
	for _, client := range t.inbClients {
		for _, obj := range t.policies {
			kind := obj.GetObjectKind().GroupVersionKind().Kind
			name := obj.GetName()
			if obj.GetNamespace() != "" {
				name = obj.GetNamespace() + "/" + name
			}

			t.log.Info(fmt.Sprintf("📜 Removing %s %s", kind, name))
			err := client.DeleteGeneric(ctx, obj)
			if err != nil && !k8serrors.IsNotFound(err) {
				t.log.Warn(fmt.Sprintf("⚠️ Failed removing %s %s: %v", kind, name, err))
			}
		}
	}

	// Reset the map, so that a subsequent call to Cleanup doesn't attempt
	// to remove the same policies again.
	t.policies = make(map[string]k8s.Object)
}

var networks = []NetworkName{NetworkA, NetworkB, NetworkC, NetworkD}

func (t *TestRun) Networks() iter.Seq[NetworkName] {
	return slices.Values(networks)
}

func (t *TestRun) INBNodeNames() iter.Seq[NodeName] {
	return maps.Keys(t.ciliumPodsINBs)
}

func (t *TestRun) ApplyExternalEndpointIngressPolicies(ctx context.Context, allowPort int) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("previous test operation failed: %w", err)
	}

	for _, client := range t.inbClients {
		networkPolicies := []k8s.Object{}

		for _, nets := range t.ext {
			for _, vm := range nets {
				policies, err := t.renderNetworkPolicies(string(vm.Name), allowPort)
				if err != nil {
					return err
				}
				networkPolicies = append(networkPolicies, policies...)
				for _, policy := range policies {
					t.policies[policy.GetNamespace()+"/"+policy.GetName()] = policy
				}
			}
		}
		if err := t.applyObjs(ctx, client, networkPolicies); err != nil {
			return err
		}
	}
	return nil
}

func (t *TestRun) applyObjs(ctx context.Context, client *enterpriseK8s.EnterpriseClient, toApply []k8s.Object) error {
	for _, obj := range toApply {
		kind := obj.GetObjectKind().GroupVersionKind().Kind
		name := obj.GetName()
		if namespace := obj.GetNamespace(); namespace != "" {
			name = namespace + "/" + name
		}
		t.log.Info(fmt.Sprintf("📜 Applying %s %s on cluster %s", kind, name, client.ClusterName()))
		_, err := client.ApplyGeneric(ctx, obj)
		if err != nil {
			return fmt.Errorf("failed applying %s %s on cluster %s: %w", kind, name, client.ClusterName(), err)
		}
	}
	return nil
}

func (t *TestRun) theFamilies(overrides ...features.IPFamily) iter.Seq[features.IPFamily] {
	if len(overrides) == 0 {
		return slices.Values(t.families)
	}

	return func(yield func(features.IPFamily) bool) {
		for _, fam := range overrides {
			if slices.Contains(t.families, fam) {
				if !yield(fam) {
					return
				}
			}
		}
	}
}

func renderTemplate(templ string, data any) (string, error) {
	t, err := template.New("template").Funcs(template.FuncMap{
		// Slightly adapted version of:
		// https://github.com/Masterminds/sprig/blob/8cb06fe3c8b0f1163c26b0a558669da72ee14656/strings.go#L109-L112
		"indent": func(spaces int, v string) string {
			pad := strings.Repeat(" ", spaces)
			return strings.ReplaceAll(v, "\n", "\n"+pad)
		},
	}).Parse(templ)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
