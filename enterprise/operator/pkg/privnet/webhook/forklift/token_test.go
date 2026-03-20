// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package forklift

import (
	"context"
	"os"
	"path"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestTokenVault(t *testing.T) {
	testutils.GoleakVerifyNone(t)

	var (
		log     = hivetest.Logger(t)
		tmp     = t.TempDir()
		target  = path.Join(tmp, "token")
		fixture = func(into *TokenVault) *hive.Hive {
			return hive.New(
				cell.Provide(func(lc cell.Lifecycle, jg job.Group) TokenVault {
					return newTokenVault(target, lc, jg)
				}),

				cell.Invoke(func(v TokenVault) { *into = v }),
			)
		}
	)

	t.Run("not-exists", func(t *testing.T) {
		var vault TokenVault
		// The file doesn't exist, hence hive.Start should fail
		require.ErrorContains(t, fixture(&vault).Start(log, t.Context()), "reading bearer token: open")
	})

	t.Run("exists", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var (
				vault TokenVault
				h     = fixture(&vault)
			)

			require.NoError(t, os.WriteFile(target, []byte("foo"), 0644), "os.WriteFile")

			// The file does exist, hence hive.Start should succeed.
			require.NoError(t, h.Start(log, t.Context()), "hive.Start")
			t.Cleanup(func() {
				require.NoError(t, h.Stop(log, context.Background()), "hive.Start")
			})

			require.Equal(t, "foo", vault.Token())
			synctest.Wait()

			require.NoError(t, os.WriteFile(target, []byte("bar"), 0644), "os.WriteFile")
			time.Sleep(5 * time.Minute)
			synctest.Wait()

			require.Equal(t, "bar", vault.Token())

			require.NoError(t, os.Remove(target), "os.Remove")
			time.Sleep(5 * time.Minute)
			synctest.Wait()

			// Refresh has failed, but the vault should still return the previous token.
			require.Equal(t, "bar", vault.Token())

			require.NoError(t, os.WriteFile(target, []byte("qux"), 0644), "os.WriteFile")
			time.Sleep(5 * time.Minute)
			synctest.Wait()

			require.Equal(t, "qux", vault.Token())
		})
	})

}
