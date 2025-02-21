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
)

type FailureReporter interface {
	Failedf(msg string, args ...interface{})
}

type T interface {
	FailureReporter
	Name() string
	RegisterCleanup(f func() error)
	Context() context.Context
}

type LbTestFunc struct {
	ctx       context.Context
	name      string
	testFunc  func(t T)
	failed    bool
	cleanupCb []func()
}

func NewLBTestFunc(ctx context.Context, testFunc func(t T)) *LbTestFunc {
	return &LbTestFunc{
		ctx:       ctx,
		name:      testName(testFunc),
		testFunc:  testFunc,
		cleanupCb: []func(){},
	}
}

func (r *LbTestFunc) Name() string {
	return r.name
}

func (r *LbTestFunc) Run() {
	r.RegisterCleanup(r.sysdump)
	r.testFunc(r)
	r.runCleanups()
}

func (r *LbTestFunc) Context() context.Context {
	return r.ctx
}

func (r *LbTestFunc) sysdump() error {
	if !FlagSysdumpOnFailure || !r.failed {
		return nil
	}

	cmd := exec.Command(FlagCiliumCLIPath, "sysdump", "--output-filename", "cilium-sysdump-"+r.name)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start sysdump collection: %w", err)
	}

	return nil
}

func (r *LbTestFunc) Failedf(msg string, args ...interface{}) {
	r.failed = true

	fmt.Fprintf(os.Stderr, "\nILB test func failed with error: %s\n", fmt.Sprintf(msg, args...))
	r.runCleanups()
	os.Exit(1)
}

// RegisterCleanup registers a function to be called when the test function completes.
// Cleanup functions will be executed if cleanup functionality is enabled and
// will called in last added, first called order.
func (r *LbTestFunc) RegisterCleanup(f func() error) {
	if FlagCleanup {
		r.cleanupCb = append(r.cleanupCb, func() {
			if err := f(); err != nil {
				fmt.Printf("cleanup failed %s\n", err)
			}
		})
	}
}

func (r *LbTestFunc) runCleanups() {
	for _, f := range slices.Backward(r.cleanupCb) {
		f()
	}

	r.cleanupCb = []func(){}
}

func testName(f func(t T)) string {
	testFuncNameFull := strings.Split(runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name(), ".")
	return testFuncNameFull[len(testFuncNameFull)-1]
}
