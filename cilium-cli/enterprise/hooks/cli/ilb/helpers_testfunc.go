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
	"os/exec"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"time"
)

type FailureReporter interface {
	Failedf(msg string, args ...any)
}

type T interface {
	FailureReporter
	Name() string
	RegisterCleanup(f func(ctx context.Context) error)
	RunTestCase(f func(t T))
	Context() context.Context
	Log(msg string, a ...any)
	CiliumNamespace() string
}

type LbTestFunc struct {
	run       *lbTestRun
	ctx       context.Context
	name      string
	testFunc  func(t T)
	failed    bool
	cleanupCb []func(ctx context.Context) error
	// stored log messages to replay for failed tests in non-verbose mode
	storedLogMsgs []string
}

func NewLBTestFunc(run *lbTestRun, ctx context.Context, testFunc func(t T)) *LbTestFunc {
	return &LbTestFunc{
		run:       run,
		ctx:       ctx,
		name:      testNameFromFunc(testFunc),
		testFunc:  testFunc,
		cleanupCb: []func(ctx context.Context) error{},
	}
}

func (r *LbTestFunc) Name() string {
	return r.name
}

func (r *LbTestFunc) Run() {
	r.testFunc(r)
	r.runCleanups()
}

func (r *LbTestFunc) Context() context.Context {
	return r.ctx
}

func (r *LbTestFunc) Log(msg string, a ...any) {
	if !FlagVerbose {
		r.storedLogMsgs = append(r.storedLogMsgs, fmt.Sprintf(msg, a...))
		return
	}

	fmt.Printf(msg+"\n", a...)
}

func (r *LbTestFunc) CiliumNamespace() string {
	return r.run.ciliumNamespace
}

func (r *LbTestFunc) sysdump() error {
	if !FlagSysdumpOnFailure || !r.failed {
		return nil
	}

	fmt.Printf("Capturing sysdump\n")

	cmd := exec.Command(FlagCiliumCLIPath, "sysdump", "--output-filename", FlagSysdumpOutputFilename)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start sysdump collection: %w", err)
	}

	return nil
}

func (r *LbTestFunc) Failedf(msg string, args ...any) {
	r.failed = true

	if !FlagVerbose {
		// output log messages for failed test in non-verbose mode
		for _, m := range r.storedLogMsgs {
			fmt.Println(m)
		}
	}

	fmt.Fprintf(os.Stderr, "\nILB test func %q failed with error: %s\n", r.Name(), fmt.Sprintf(msg, args...))
	r.runCleanups()
	r.run.Failed()
}

// RegisterCleanup registers a function to be called when the test function completes.
// Cleanup functions will be executed if cleanup functionality is enabled and
// will called in last added, first called order.
func (r *LbTestFunc) RegisterCleanup(f func(ctx context.Context) error) {
	r.cleanupCb = append(r.cleanupCb, f)
}

func (r *LbTestFunc) RunTestCase(f func(t T)) {
	f(r)
	r.runCleanups()
}

func (r *LbTestFunc) runCleanups() {
	// Get sysdump independent of whether cleanups are enabled or not.
	if err := r.sysdump(); err != nil {
		fmt.Printf("Capturing sysdump failed: %s\n", err)
	}

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

func testNameFromFunc(f func(t T)) string {
	testFuncNameFull := strings.Split(runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name(), ".")
	return testFuncNameFull[len(testFuncNameFull)-1]
}
