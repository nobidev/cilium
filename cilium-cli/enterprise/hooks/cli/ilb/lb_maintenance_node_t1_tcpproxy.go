//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	isovalentv1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/versioncheck"
)

func TestNodeMaintenance_T1_T1T2_TCPProxy(t T) {
	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	// node maintenance is only supported in v1.18 and newer
	minVersion := ">=1.18.0"
	currentVersion := GetCiliumVersion(t, k8sCli)
	if !versioncheck.MustCompile(minVersion)(currentVersion) {
		fmt.Printf("skipping due to version mismatch - expected: %s - current: %s\n", minVersion, currentVersion.String())
		return
	}

	// Skip test in environments with only one T1 node instance because this breaks connection
	t1NodeList, err := k8sCli.CoreV1().Nodes().List(t.Context(), metav1.ListOptions{LabelSelector: "service.cilium.io/node in ( t1, t1-t2 )"})
	if err != nil {
		t.Failedf("failed to retrieve t1 k8s nodes: %s", err)
	}

	t2NodeList, err := k8sCli.CoreV1().Nodes().List(t.Context(), metav1.ListOptions{LabelSelector: "service.cilium.io/node in ( t2, t1-t2 )"})
	if err != nil {
		t.Failedf("failed to retrieve t2 k8s nodes: %s", err)
	}

	if len(t1NodeList.Items) < 2 {
		fmt.Printf("skipping due to not at least 2 T1 nodes available\n")
		return
	}

	t.RunTestCase(func(t T) {
		mode := isovalentv1alpha1.LBTCPProxyForceDeploymentModeT2
		testName := "node-maintenance-t1-tcp-proxy-" + string(mode)

		//
		// Setup test scenario (backends, clients & LB resources)
		//
		scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

		t.Log("Creating backend apps...")
		scenario.addBackendApplications(1, backendApplicationConfig{h2cEnabled: true, image: FlagMariaDBImage, listenPort: mySqlPort, envVars: map[string]string{"MARIADB_ROOT_PASSWORD": mySqlPassword}})

		t.Log("Creating clients and add BGP peering ...")
		client := scenario.addFRRClients(1, frrClientConfig{})[0]

		t.Log("Creating LB VIP resources...")
		vip := lbVIP(testName)
		scenario.createLBVIP(vip)

		t.Log("Creating LB BackendPool resources...")
		backends := []backendPoolOption{
			withTCPHealthCheck(nil, nil),
		}

		sqlServerIP := ""
		sqlServerPort := uint32(0)

		for _, b := range scenario.backendApps {
			sqlServerIP = b.ip
			sqlServerPort = b.port
			backends = append(backends, withIPBackend(b.ip, b.port))
		}

		backendPool := lbBackendPool(testName, backends...)
		scenario.createLBBackendPool(backendPool)

		t.Log("Creating LB Service resources...")
		service := lbService(testName, withPort(80), withTCPProxyApplication(withTCPForceDeploymentMode(mode), withTCPProxyRoute(backendPool.Name)))
		scenario.createLBService(service)

		t.Log("Waiting for full VIP connectivity...")
		vipIP := scenario.waitForFullVIPConnectivity(testName)

		// Additional check to prevent the persistent connection from being killed because there's not a single healthy T2 endpoint available.
		// This can be caused for two reasons:
		// 1. Initial BGP status / Service health flapping. The service gets created in `healthy` state and then gets reconciled based on the active health check.
		//    In this short period, the service might already be advertised via BGP (initial state healthy) and gets withdraw immediately after (endpoint not ready yet).
		// 2. There's only one healthy T2 instance at the time of testing - and that's the one that gets put into maintenance
		//
		// In both cases, the BGP route gets withdraw if there's no healthy (T2) endpoint available. Which leads to terminating the persistent connection if the same happens on all T1 nodes.
		t.Log("Waiting until all T2 endpoints are active on all T1 nodes...")
		scenario.waitForAllT2EndpointsActive(testName, vipIP, 80, t1NodeList, t2NodeList)

		//
		// Actual start of tests
		//
		testCmd := fmt.Sprintf("lb-test-client sql %s:%s@tcp(%s:%s)/%s", mySqlUser, mySqlPassword, vipIP, "80", "sys")
		t.Log("Starting SQL client that opens TCP connection %q...", testCmd)
		testClientOutputReader, err := client.ExecDetached(t.Context(), []string{"lb-test-client", "sql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", mySqlUser, mySqlPassword, vipIP, "80", "sys")})
		if err != nil {
			t.Failedf("failed to start sql client (cmd: %q): %s", testCmd, err)
		}

		if FlagVerbose {
			go func() {
				if _, err := io.Copy(os.Stdout, testClientOutputReader); err != nil {
					fmt.Printf("failed to copy test app output: %s\n", err)
				}
			}()
		}

		t.Log("Waiting for connection on SQL server side...")
		t2NodeIP, t2NodeSourcePort, connTimeout := waitForConnectionOnSQLServer(t, client, sqlServerIP, sqlServerPort)

		t.Log("Connection found with client IP %s, port %s and timeout %s", t2NodeIP, t2NodeSourcePort, connTimeout)

		t.Log("Looping through all T1 nodes and check that they are used for BGP")

		for _, t1Node := range t1NodeList.Items {
			t.Log("Checking that T1 node %s is used as route", t1Node.Name)
			eventually(t, func() error {
				peerIP := getNodeIP(t1Node)
				if err := client.EnsureRouteVia(t.Context(), vipIP+"/32", peerIP); err != nil {
					return fmt.Errorf("the route %s/32 via %s (%s) doesn't exist", vipIP, peerIP, t1Node.Name)
				}
				return nil
			}, shortTimeout, pollInterval)
		}

		t.Log("Looping through all T1 nodes and marking them as unschedulable")
		//  register cleanup to revert all k8s nodes to be schedulable (in case we abort early due to an error)
		t.RegisterCleanup(markAllNodesAsSchedulable(k8sCli))
		for _, t1Node := range t1NodeList.Items {

			if nodeIsT1AndT2(&t1Node) {
				t.Log("Mark T1 node %s for maintenance via BGP node config override with mode withdrawal", t1Node.Name)
				createBGPNodeConfigOverrideWithMaintenance(t, ciliumCli, t1Node.Name, isovalentv1.BGPMaintenanceModeWithdrawal)
			} else {
				t.Log("Mark T1 node %s for maintenance by marking it as unschedulable", t1Node.Name)
				markNodeAsUnschedulable(t, k8sCli, t1Node.Name)
			}

			t.Log("Waiting until routes for VIP via T1 node in maintenance (%s) is withdrawn...", t1Node.Name)
			eventually(t, func() error {
				peerIP := getNodeIP(t1Node)
				if err := client.EnsureRouteVia(t.Context(), vipIP+"/32", peerIP); err == nil {
					return fmt.Errorf("the route %s/32 via %s (%s) still exists", vipIP, peerIP, t1Node.Name)
				}
				return nil
			}, shortTimeout, pollInterval)

			t.Log("Wait 20s (longer than the next ping interval (5s) plus timeout (10s) of the test application)...")
			time.Sleep(20 * time.Second)

			if nodeIsT1AndT2(&t1Node) {
				// This step is necessary for nodes that serve T1 & T2 functionality. If T1 & T2 are put into maintenance
				// by marking the node as unschedulable it will break existing persistent connections.
				t.Log("Delete BGPNodeConfigOverride for T1 node %s", t1Node.Name)
				ciliumCli.IsovalentV1().IsovalentBGPNodeConfigOverrides().Delete(t.Context(), t1Node.Name, metav1.DeleteOptions{})
			} else {
				t.Log("Mark T1 node %s back as schedulable", t1Node.Name)
				markNodeAsSchedulable(t, k8sCli, t1Node.Name)
			}

			t.Log("Checking that T1 node %s is used as route again", t1Node.Name)
			eventually(t, func() error {
				peerIP := getNodeIP(t1Node)
				if err := client.EnsureRouteVia(t.Context(), vipIP+"/32", peerIP); err != nil {
					return fmt.Errorf("the route %s/32 via %s (%s) doesn't exist", vipIP, peerIP, t1Node.Name)
				}
				return nil
			}, shortTimeout, pollInterval)

			// some extra time
			time.Sleep(5 * time.Second)
		}

		t.Log("Checking existing connection is still alive / pinged")
		checkInitialConnectionAlive(t, client, sqlServerIP, sqlServerPort, t2NodeIP, t2NodeSourcePort)
	})
}

func createBGPNodeConfigOverrideWithMaintenance(t T, ciliumCli *ciliumCli, nodeName string, maintenanceMode isovalentv1.BGPMaintenanceMode) {
	_, err := ciliumCli.IsovalentV1().IsovalentBGPNodeConfigOverrides().Create(t.Context(), &isovalentv1.IsovalentBGPNodeConfigOverride{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
		},
		Spec: isovalentv1.IsovalentBGPNodeConfigOverrideSpec{
			BGPInstances: []isovalentv1.IsovalentBGPNodeConfigInstanceOverride{{
				Name: "t1",
				Maintenance: &isovalentv1.IsovalentBGPMaintenance{
					Mode: maintenanceMode,
				},
			}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Failedf("failed to create BGP node config override %s: %s", nodeName, err)
	}

	t.RegisterCleanup(func(ctx context.Context) error {
		_ = ciliumCli.IsovalentV1().IsovalentBGPNodeConfigOverrides().Delete(t.Context(), nodeName, metav1.DeleteOptions{})
		return nil // drop error
	})
}
