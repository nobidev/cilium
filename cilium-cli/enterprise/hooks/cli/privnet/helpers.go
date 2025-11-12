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
	"errors"

	"k8s.io/client-go/util/exec"
)

func extractExitCode(err error) (exitCode int, ok bool) {
	var execErr exec.ExitError
	if errors.As(err, &execErr) {
		exitCode = execErr.ExitStatus()
	} else if err != nil {
		return 0, false
	}
	return exitCode, true
}

func curlCmd(destination string) []string {
	return []string{
		"curl", "--silent", "--fail", "--show-error", "--connect-timeout", "2", "--max-time", "10", destination,
	}
}
