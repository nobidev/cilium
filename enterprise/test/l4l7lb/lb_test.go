//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package l4l7lb

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	scheme "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
)

//go:embed manifests/lb-vips.yaml
var yamlLBVIPs string

//go:embed manifests/lb-frontends.yaml
var yamlLBFrontends string

//go:embed manifests/lb-backends.yaml
var yamlLBBackends string

//go:embed manifests/lb-ippools.yaml
var yamlLBIPPools string

const (
	defaultNamespace = "default"

	clientContainerName = "frr"
)

type lbTests struct {
	ciliumCli *ciliumCli
	dockerCli *dockerCli

	vips map[int]string
}

func (lbt *lbTests) installLBObjs(ctx context.Context, t *testing.T) {
	// 1. Install LB VIPS

	lbVIPs, err := yamlToObjects[*isovalentv1alpha1.LBVIP](yamlLBVIPs, scheme.Scheme)
	if err != nil {
		t.Fatalf("Failed to deserialize LB VIP: %s", err)
	}

	for _, obj := range lbVIPs {
		lbt.ciliumCli.DeleteLBVIP(ctx, defaultNamespace, obj.GetObjectMeta().GetName(), metav1.DeleteOptions{})

		t.Logf("Creating LB VIP %s...", obj.GetObjectMeta().GetName())
		if err := lbt.ciliumCli.CreateLBVIP(ctx, defaultNamespace, obj, metav1.CreateOptions{}); err != nil {
			t.Fatalf("Failed to create LB VIP: %s", err)
		}
	}

	// 2. Install LB Frontends

	frontends, err := yamlToObjects[*isovalentv1alpha1.LBFrontend](yamlLBFrontends, scheme.Scheme)
	if err != nil {
		t.Fatalf("Failed to deserialize LB Frontend: %s", err)
	}

	for _, obj := range frontends {
		lbt.ciliumCli.DeleteLBFrontend(ctx, defaultNamespace, obj.GetObjectMeta().GetName(), metav1.DeleteOptions{})

		t.Logf("Creating LB Frontend %s...", obj.GetObjectMeta().GetName())
		if err := lbt.ciliumCli.CreateLBFrontend(ctx, "default", obj, metav1.CreateOptions{}); err != nil {
			t.Fatalf("Failed to create LB VIP: %s", err)
		}
	}

	// 3. Install LB Backends

	backends, err := yamlToObjects[*isovalentv1alpha1.LBBackendPool](yamlLBBackends, scheme.Scheme)
	if err != nil {
		t.Fatalf("Failed to deserialize LB Backend: %s", err)
	}

	appIPAddrs := map[int]string{}
	for i := 1; i <= 5; i++ {
		ip, err := lbt.dockerCli.GetContainerIP(ctx, fmt.Sprintf("app%d", i))
		if err != nil {
			t.Fatalf("Failed to retrieve container app%d IP: %s", i, err)
		}
		if ip == "" {
			t.Fatalf("app%d does not have any IP addr", i)
		}
		appIPAddrs[i] = ip
	}

	backends[0].Spec.Backends[0].IP = appIPAddrs[1]
	backends[0].Spec.Backends[1].IP = appIPAddrs[2]

	backends[1].Spec.Backends[0].IP = appIPAddrs[1]
	backends[1].Spec.Backends[1].IP = appIPAddrs[3]

	backends[2].Spec.Backends[0].IP = appIPAddrs[2]
	backends[2].Spec.Backends[1].IP = appIPAddrs[3]

	backends[3].Spec.Backends[0].IP = appIPAddrs[2]
	backends[3].Spec.Backends[1].IP = appIPAddrs[3]

	backends[4].Spec.Backends[0].IP = appIPAddrs[2]
	backends[4].Spec.Backends[1].IP = appIPAddrs[3]

	backends[5].Spec.Backends[0].IP = appIPAddrs[4]

	backends[6].Spec.Backends[0].IP = appIPAddrs[5]

	for _, obj := range backends {
		lbt.ciliumCli.DeleteLBBackend(ctx, defaultNamespace, obj.GetObjectMeta().GetName(), metav1.DeleteOptions{})

		t.Logf("Creating LB Backend %s...", obj.GetObjectMeta().GetName())
		if err := lbt.ciliumCli.CreateLBBackend(ctx, "default", obj, metav1.CreateOptions{}); err != nil {
			t.Fatalf("Failed to create LB Backend: %s", err)
		}
	}

	// 4. Install LB IPPOOLS

	lbIPPools, err := yamlToObjects[*ciliumv2alpha1.CiliumLoadBalancerIPPool](yamlLBIPPools, scheme.Scheme)
	if err != nil {
		t.Fatalf("Failed to deserialize LB IP Pool: %s", err)
	}

	for _, obj := range lbIPPools {
		t.Logf("Creating LB IP Pool %s...", obj.GetObjectMeta().GetName())
		if err := lbt.ciliumCli.CreateLBIPPool(ctx, obj, metav1.CreateOptions{}); err != nil {
			t.Logf("Failed to create LB IP Pool: %s", err)
		}
	}

	// 5. Wait for LB VIPs

	for i := 1; i <= 6; i++ {
		name := fmt.Sprintf("lb-%d", i)
		t.Logf("Waiting for LB VIP %s...", name)
		vip, err := lbt.ciliumCli.WaitForLBVIP(ctx, defaultNamespace, name)
		if err != nil {
			t.Fatalf("Failed to wait for LB VIP %s: %s", name, err)
		}
		lbt.vips[i] = vip
	}

}

func (lbt *lbTests) testBasicLBConnectivity(ctx context.Context, t *testing.T) {
	testCmds := []string{
		curlCmd(fmt.Sprintf("--cacert /tmp/tls-secure.crt --resolve secure.acme.io:443:%s https://secure.acme.io:443/", lbt.vips[1])),
		curlCmd(fmt.Sprintf("--resolve insecure.acme.io:80:%s http://insecure.acme.io:80/api/foo-insecure", lbt.vips[2])),
		curlCmd(fmt.Sprintf("http://%s:81/", lbt.vips[3])),
		curlCmd(fmt.Sprintf("--resolve mixed.acme.io:80:%s http://mixed.acme.io:80/", lbt.vips[4])),
		curlCmd(fmt.Sprintf("--cacert /tmp/tls-secure80.crt --resolve secure-80.acme.io:80:%s https://secure-80.acme.io:80/", lbt.vips[5])),
		curlCmd(fmt.Sprintf("--cacert /tmp/tls-secure-backend.crt --resolve passthrough.acme.io:80:%s https://passthrough.acme.io:80/", lbt.vips[6])),
		curlCmd(fmt.Sprintf("--cacert /tmp/tls-secure-backend2.crt --resolve passthrough-2.acme.io:80:%s https://passthrough-2.acme.io:80/", lbt.vips[6])),
	}

	for _, cmd := range testCmds {
		stdout, stderr, err := lbt.clientExec(ctx, cmd, t)
		fmt.Println(stdout, stderr)
		if err != nil {
			t.Fatalf("Failed cmd %q: %s (stdout: %s, stderr: %s)", cmd, err, stdout, stderr)
		}
	}
}

func (lbt *lbTests) clientExec(ctx context.Context, cmd string, t *testing.T) (string, string, error) {
	t.Logf("Running client cmd %q...", cmd)

	stdout, stderr, err := lbt.dockerCli.ContainerExec(ctx, clientContainerName,
		[]string{"bash", "-c", cmd},
	)

	return stdout, stderr, err
}

func TestLB(t *testing.T) {
	if os.Getenv("LOADBALANCER_TESTS") != "true" {
		t.Skip("Skipping due to LOADBALANCER_TESTS!=true")
	}

	ctx := context.Background()

	ciliumCli, err := newCiliumCli()
	if err != nil {
		t.Fatalf("Failed to create Cilium client: %s", err)
	}

	dockerCli, err := newDockerCli()
	if err != nil {
		t.Fatalf("Failed to create Docker client: %s", err)
	}

	lbt := &lbTests{
		ciliumCli: ciliumCli,
		dockerCli: dockerCli,
		vips:      map[int]string{},
	}

	lbt.installLBObjs(ctx, t)
	// TODO(brb) defer lbt.cleanup()

	lbt.testBasicLBConnectivity(ctx, t)
}
