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
	"fmt"
	"os"
	"os/exec"
)

func MaybeSysdump(testName string) {
	if !FlagSysdumpOnFailure {
		return
	}

	MaybeCleanupT(func() error {
		if !testFailed {
			return nil
		}

		cmd := exec.Command(FlagCiliumCLIPath, "sysdump", "--output-filename", "cilium-sysdump-"+testName)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("Failed to start sysdump collection: %w", err)
		}

		return nil
	})
}
