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
	"fmt"
	"testing"
)

var cleanup = flag.Bool("cleanup", true, "Cleanup created resources after each test case run")

func maybeCleanupT(f func() error, t *testing.T) {
	if *cleanup {
		t.Cleanup(func() {
			if err := f(); err != nil {
				fmt.Printf("cleanup failed %s\n", err)
			}
		})
	}
}

func maybeCleanup(f func() error) {
	if *cleanup {
		if err := f(); err != nil {
			fmt.Printf("cleanup failed: %s\n", err)
		}
	}
}
