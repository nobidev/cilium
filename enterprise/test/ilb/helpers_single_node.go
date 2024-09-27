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
	"flag"
	"testing"
)

var flagMode = flag.String("mode", "multi-node", "Testing mode ('multi-node' or 'single-node'). 'multi-node' deploys client and LB app containers in separate network namespaces (to simulate multi-node LB environments). 'single-node' deploys the containers on a single node in the same host network namespace.")
var flagSingleNodeIPAddr = flag.String("single-node-ip", "", "The IP addr of the test runner node. The IP addr should be reachable by T1 and T2 nodes. Required when --mode=single-node.")

func isSingleNode() bool {
	return *flagMode == "single-node"
}

func getSingleNodeIPAddr() string {
	return *flagSingleNodeIPAddr
}

func skipIfOnSingleNode(t *testing.T, msg string) {
	if isSingleNode() {
		t.Skipf("skipping due to single-mode: %s", msg)
	}
}
