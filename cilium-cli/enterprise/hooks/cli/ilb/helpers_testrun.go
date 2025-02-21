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
	"os"
	"regexp"
	"slices"
)

type lbTestRun struct {
	cleanupCb []func() error
}

func NewLBTestRun(ctx context.Context) *lbTestRun {
	return &lbTestRun{
		cleanupCb: []func() error{},
	}
}

func (r *lbTestRun) ExecuteTestFuncs(ctx context.Context) error {
	runRegexp, err := regexp.Compile(FlagRun)
	if err != nil {
		return fmt.Errorf("failed to parse run regexp (%s): %w", FlagRun, err)
	}

	testsToExecute := []*LbTestFunc{}

	for _, test := range Tests {
		tf := NewLBTestFunc(r, ctx, test)
		testFuncName := tf.Name()
		if runRegexp.Match([]byte(testFuncName)) {
			testsToExecute = append(testsToExecute, tf)
		}
	}

	for i, test := range testsToExecute {
		fmt.Printf("=== [%02d/%02d] %s\n", i+1, len(testsToExecute), test.Name())
		test.Run()
		if !FlagQuiet {
			// newline to highlight start of new test function
			fmt.Println()
		}
	}

	return nil
}

func (r *lbTestRun) Failedf(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, "\nILB testrun failed with error: %s\n", fmt.Sprintf(msg, args...))
	r.Failed()
}

func (r *lbTestRun) Failed() {
	r.RunCleanup()
	os.Exit(1)
}

// RegisterCleanup registers a cleanup that gets executed when the testrun ends.
func (r *lbTestRun) RegisterCleanup(f func() error) {
	r.cleanupCb = append(r.cleanupCb, f)
}

func (r *lbTestRun) RunCleanup() {
	if !FlagCleanup {
		return
	}

	for _, f := range slices.Backward(r.cleanupCb) {
		if err := f(); err != nil {
			fmt.Printf("cleanup failed %s\n", err)
		}
	}

	r.cleanupCb = []func() error{}
}
