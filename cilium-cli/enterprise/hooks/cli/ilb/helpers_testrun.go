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
	"strings"
	"time"
)

type lbTestRun struct {
	cleanupCb []func(ctx context.Context) error
}

func NewLBTestRun(ctx context.Context) *lbTestRun {
	return &lbTestRun{
		cleanupCb: []func(ctx context.Context) error{},
	}
}

func (r *lbTestRun) ExecuteTestFuncs(ctx context.Context) error {
	runRegexp := []*regexp.Regexp{}
	skipRegexp := []*regexp.Regexp{}
	for _, r := range FlagRun {
		if strings.HasPrefix(r, "!") {
			rgx, err := regexp.Compile(strings.TrimPrefix(r, "!"))
			if err != nil {
				return fmt.Errorf("failed to parse run-tests regexp (%s): %w", r, err)
			}
			skipRegexp = append(skipRegexp, rgx)
		} else {
			rgx, err := regexp.Compile(r)
			if err != nil {
				return fmt.Errorf("failed to parse run-tests regexp (%s): %w", r, err)
			}
			runRegexp = append(runRegexp, rgx)
		}
	}

	testsToExecute := []*LbTestFunc{}
	for _, test := range Tests {
		tf := NewLBTestFunc(r, ctx, test)
		testFuncName := tf.Name()

		skip := false
		for _, rgx := range skipRegexp {
			if rgx.Match([]byte(testFuncName)) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		for _, rgx := range runRegexp {
			if rgx.Match([]byte(testFuncName)) {
				testsToExecute = append(testsToExecute, tf)
			}
		}

		// Previously there was only a single regexp: ""
		// This always matched all test names, so now we need this check.
		if len(runRegexp) == 0 {
			testsToExecute = append(testsToExecute, tf)
		}
	}

	for i, test := range testsToExecute {
		select {
		case <-ctx.Done():
			fmt.Println("Cancelled - stopping test execution...")
			return nil
		default:
			fmt.Printf("=== [%02d/%02d] %s\n", i+1, len(testsToExecute), test.Name())
			test.Run()
			if FlagVerbose {
				// newline to highlight start of new test function in verbose mode
				fmt.Println()
			}
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
func (r *lbTestRun) RegisterCleanup(f func(ctx context.Context) error) {
	r.cleanupCb = append(r.cleanupCb, f)
}

func (r *lbTestRun) RunCleanup() {
	if !FlagCleanup {
		return
	}

	cleanupCtx, cancelCleanupCtx := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancelCleanupCtx()

	for _, f := range slices.Backward(r.cleanupCb) {
		if err := f(cleanupCtx); err != nil {
			fmt.Printf("cleanup failed %s\n", err)
		}
	}

	r.cleanupCb = []func(ctx context.Context) error{}
}
