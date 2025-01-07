/*
Copyright (C) Isovalent, Inc. - All Rights Reserved.

NOTICE: All information contained herein is, and remains the property of
Isovalent Inc and its suppliers, if any. The intellectual and technical
concepts contained herein are proprietary to Isovalent Inc and its suppliers
and may be covered by U.S. and Foreign Patents, patents in process, and are
protected by trade secret or copyright law.  Dissemination of this information
or reproduction of this material is strictly forbidden unless prior written
permission is obtained from Isovalent Inc.
*/

package main

import (
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/isovalent/cilium/enterprise/olm/manager"
)

func main() {
	// the implementation is moved to a separate function that can be called by E2E tests
	ctx := ctrl.SetupSignalHandler()
	manager.Start(ctx)
}
