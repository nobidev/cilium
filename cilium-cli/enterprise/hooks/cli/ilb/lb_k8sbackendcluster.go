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

func TestLBK8sBackendClusterConnectivity(t T) {
	if skipIfOnSingleNode("backend kind clusters require a shared Docker network") {
		return
	}

	testName := "lbk8sbackend-connect"
	backendClusterName := "ilb-backend"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend kind cluster...")
	backendCluster := scenario.createBackendKindCluster(backendClusterName)

	t.Log("Waiting for backend cluster to be ready...")
	scenario.waitForBackendKindClusterReady(backendCluster)

	t.Log("Creating kubeconfig secret...")
	secretName := testName + "-kubeconfig"
	scenario.createLBK8sBackendClusterSecret(backendCluster, secretName)

	t.Log("Creating LBK8sBackendCluster resource...")
	lbK8sBackendClusterName := testName + "-cluster"
	scenario.createLBK8sBackendCluster(lbK8sBackendClusterName, secretName, scenario.k8sNamespace)

	t.Log("Waiting for LBK8sBackendCluster to connect...")
	scenario.waitForLBK8sBackendClusterConnected(lbK8sBackendClusterName)
}

func TestLBK8sBackendClusterMultiple(t T) {
	if skipIfOnSingleNode("backend kind clusters require a shared Docker network") {
		return
	}

	testName := "lbk8sbackend-multiple"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating first backend kind cluster...")
	backendCluster1 := scenario.createBackendKindCluster("ilb-backend-1")

	t.Log("Creating second backend kind cluster...")
	backendCluster2 := scenario.createBackendKindCluster("ilb-backend-2")

	t.Log("Waiting for backend clusters to be ready...")
	scenario.waitForBackendKindClusterReady(backendCluster1)
	scenario.waitForBackendKindClusterReady(backendCluster2)

	t.Log("Creating kubeconfig secrets...")
	secretName1 := testName + "-kubeconfig-1"
	secretName2 := testName + "-kubeconfig-2"
	scenario.createLBK8sBackendClusterSecret(backendCluster1, secretName1)
	scenario.createLBK8sBackendClusterSecret(backendCluster2, secretName2)

	t.Log("Creating LBK8sBackendCluster resources...")
	lbK8sBackendClusterName1 := testName + "-cluster-1"
	lbK8sBackendClusterName2 := testName + "-cluster-2"
	scenario.createLBK8sBackendCluster(lbK8sBackendClusterName1, secretName1, scenario.k8sNamespace)
	scenario.createLBK8sBackendCluster(lbK8sBackendClusterName2, secretName2, scenario.k8sNamespace)

	t.Log("Waiting for LBK8sBackendClusters to connect...")
	scenario.waitForLBK8sBackendClusterConnected(lbK8sBackendClusterName1)
	scenario.waitForLBK8sBackendClusterConnected(lbK8sBackendClusterName2)
}

func TestLBK8sBackendClusterReconnect(t T) {
	if skipIfOnSingleNode("backend kind clusters require a shared Docker network") {
		return
	}

	testName := "lbk8sbackend-reconnect"
	backendClusterName := "ilb-backend-reconnect"

	ciliumCli, k8sCli := NewCiliumAndK8sCli(t)
	dockerCli := NewDockerCli(t)

	scenario := newLBTestScenario(t, testName, ciliumCli, k8sCli, dockerCli)

	t.Log("Creating backend kind cluster...")
	backendCluster := scenario.createBackendKindCluster(backendClusterName)

	t.Log("Waiting for backend cluster to be ready...")
	scenario.waitForBackendKindClusterReady(backendCluster)

	t.Log("Creating kubeconfig secret...")
	secretName := testName + "-kubeconfig"
	scenario.createLBK8sBackendClusterSecret(backendCluster, secretName)

	t.Log("Creating LBK8sBackendCluster resource...")
	lbK8sBackendClusterName := testName + "-cluster"
	scenario.createLBK8sBackendCluster(lbK8sBackendClusterName, secretName, scenario.k8sNamespace)

	t.Log("Waiting for LBK8sBackendCluster to connect...")
	scenario.waitForLBK8sBackendClusterConnected(lbK8sBackendClusterName)

	t.Log("Deleting backend kind cluster...")
	if err := scenario.deleteBackendKindCluster(backendCluster.Name); err != nil {
		t.Failedf("failed to delete backend kind cluster: %s", err)
	}

	t.Log("Waiting for LBK8sBackendCluster to disconnect...")
	scenario.waitForLBK8sBackendClusterDisconnected(lbK8sBackendClusterName)

	t.Log("Recreating backend kind cluster...")
	backendCluster = scenario.createBackendKindCluster(backendCluster.Name)

	t.Log("Waiting for backend cluster to be ready...")
	scenario.waitForBackendKindClusterReady(backendCluster)

	t.Log("Updating kubeconfig secret with new cluster credentials...")
	scenario.updateLBK8sBackendClusterSecret(backendCluster, secretName)

	t.Log("Waiting for LBK8sBackendCluster to reconnect...")
	scenario.waitForLBK8sBackendClusterConnected(lbK8sBackendClusterName)
}
