// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tests

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/synced"
)

type k8sSyncFence hive.Fence

func mockK8sCell(t testing.TB) cell.Cell {
	t.Helper()

	return cell.Group(
		cell.ProvidePrivate(
			newK8sCacheSync,
			newK8sSyncBlocker,
		),

		cell.Provide(func(k *k8sSyncBlocker) uhive.ScriptCmdsOut {
			return uhive.NewScriptCmds(map[string]script.Cmd{
				"privnet/k8s-block-sync":   k.blockSync(),
				"privnet/k8s-unblock-sync": k.unblockSync(),
			})
		}),
	)
}

func newK8sCacheSync(lifecycle cell.Lifecycle, slog *slog.Logger, jg job.Group) (synced.CacheStatus, k8sSyncFence) {
	c := make(synced.CacheStatus)
	f := hive.NewFence(lifecycle, slog)
	jg.Add(job.OneShot("wait-for-k8s-sync", func(ctx context.Context, health cell.Health) error {
		err := f.Wait(ctx)
		if err != nil {
			return err
		}
		close(c)
		return nil
	}))
	return c, f
}

type k8sSyncBlocker struct {
	fence   k8sSyncFence
	unblock chan struct{}
}

func newK8sSyncBlocker(fence k8sSyncFence) *k8sSyncBlocker {
	return &k8sSyncBlocker{
		fence: fence,
	}
}

func (k *k8sSyncBlocker) blockSync() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "prevent the k8s caches from automatically being synced during hive start",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return func(s *script.State) (stdout string, stderr string, err error) {
				if k.unblock != nil {
					return stdout, stderr, fmt.Errorf("k8s sync already blocked")
				}

				unblock := make(chan struct{})
				k.fence.Add("script-test-k8s-block-sync", func(ctx context.Context) error {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-unblock:
						return nil
					}
				})
				k.unblock = unblock
				return stdout, stderr, nil
			}, nil
		},
	)
}

func (k *k8sSyncBlocker) unblockSync() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "unblock the k8s cache sync event",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return func(s *script.State) (stdout string, stderr string, err error) {
				if k.unblock == nil {
					return stdout, stderr, fmt.Errorf("k8s sync not blocked")
				}

				close(k.unblock)
				k.unblock = nil
				return stdout, stderr, nil
			}, nil
		},
	)
}
