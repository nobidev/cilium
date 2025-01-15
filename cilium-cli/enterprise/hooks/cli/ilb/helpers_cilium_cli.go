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
	"os"
	"os/exec"
	"testing"
)

var (
	// maybeSysdump is only effective when this option is specified.
	flagSysdumpOnFailure = flag.Bool("sysdump-on-failure", false, "Collect sysdump on test failure")

	// By default, we assume cilium-cli is in the PATH. In the CI, we may want to specify custom path.
	flagCiliumCLIPath = flag.String("cilium-cli-path", "cilium", "cilium-cli binary path")
)

func maybeSysdump(t *testing.T, testName, suffix string) {
	if !*flagSysdumpOnFailure {
		return
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}

		cmd := exec.Command(*flagCiliumCLIPath, "sysdump", "--output-filename", "cilium-sysdump-"+testName+suffix)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			t.Logf("Failed to start sysdump collection: %v", err)
		}
	})
}
