//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package reconcilers

import (
	"iter"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/privnet/tables"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/safeio"
)

func TestINBsCheckpointer(t *testing.T) {
	var (
		dc = &option.DaemonConfig{StateDir: t.TempDir()}
		cp = newINBsCheckpointer(hivetest.Logger(t), dc)

		path  = filepath.Join(dc.StateDir, INBCheckpointFile)
		check = func(t *testing.T, expected string) {
			t.Helper()

			file, err := os.Open(path)
			require.NoError(t, err, "os.Open")
			data, err := safeio.ReadAllLimit(file, 10*safeio.KB)
			require.NoError(t, err, "safeio.ReadAllLimit")
			require.Equal(t, expected, strings.TrimSpace(string(data)))
		}
	)

	// The file does not exist, [Restore] should return an empty checkpoint.
	require.Empty(t, cp.Restore())

	// A checkpoint with no entries should be correctly saved.
	require.NoError(t, cp.CheckpointIfNeeded(), "CheckpointIfNeeded")
	check(t, `[]`)

	// Add a few active INBs, and verify that the checkpoint is updated correctly.
	cp.Add(tables.NetworkName("red"), tables.INBNode{Cluster: "mollusk", Name: "civet"})
	cp.Add(tables.NetworkName("blue"), tables.INBNode{Cluster: "mollusk", Name: "hyena"})

	require.NoError(t, cp.CheckpointIfNeeded(), "CheckpointIfNeeded")
	check(t, `[{"network":"blue","cluster":"mollusk","node":"hyena"},{"network":"red","cluster":"mollusk","node":"civet"}]`)

	// Perform a few more updates, and verify again the correctness.
	cp.Add(tables.NetworkName("yellow"), tables.INBNode{Cluster: "mollusk", Name: "civet"})
	cp.Remove(tables.NetworkName("blue"))
	cp.Add(tables.NetworkName("red"), tables.INBNode{Cluster: "honeybee", Name: "hyena"})
	cp.Add(tables.NetworkName("apricot"), tables.INBNode{Cluster: "mollusk", Name: "gibbon"})

	require.NoError(t, cp.CheckpointIfNeeded(), "CheckpointIfNeeded")
	check(t, `[{"network":"apricot","cluster":"mollusk","node":"gibbon"},{"network":"red","cluster":"honeybee","node":"hyena"},{"network":"yellow","cluster":"mollusk","node":"civet"}]`)

	// Check that restoration works.
	require.Equal(t, INBRestoredCheckpoint{
		tables.NetworkName("apricot"): {Network: "apricot", Cluster: "mollusk", Node: "gibbon"},
		tables.NetworkName("red"):     {Network: "red", Cluster: "honeybee", Node: "hyena"},
		tables.NetworkName("yellow"):  {Network: "yellow", Cluster: "mollusk", Node: "civet"},
	}, cp.Restore())

	// Remove a non-existing entry, the file should not be updated. We check that
	// by manually removing the file and checking that it is not created back,
	// as asserting on the modified time is not reliable.
	require.NoError(t, os.Remove(path), "os.Remove")
	cp.Remove(tables.NetworkName("non-existing"))
	require.NoError(t, cp.CheckpointIfNeeded(), "CheckpointIfNeeded")
	require.NoFileExists(t, path)

	// Same attempting to remove stale entries, in case active count matches.
	cp.RemoveStaleIfNeeded(3, nil)
	require.NoError(t, cp.CheckpointIfNeeded(), "CheckpointIfNeeded")
	require.NoFileExists(t, path)

	// Stale entries should be instead removed if the active count does not match.
	cp.RemoveStaleIfNeeded(2, func() iter.Seq[tables.PrivateNetwork] {
		return slices.Values([]tables.PrivateNetwork{{Name: "yellow"}, {Name: "red"}})
	})
	require.NoError(t, cp.CheckpointIfNeeded(), "CheckpointIfNeeded")
	check(t, `[{"network":"red","cluster":"honeybee","node":"hyena"},{"network":"yellow","cluster":"mollusk","node":"civet"}]`)

	// The removal of the existing entries should be propagated.
	cp.Remove(tables.NetworkName("yellow"))
	cp.Remove(tables.NetworkName("red"))

	require.NoError(t, cp.CheckpointIfNeeded(), "CheckpointIfNeeded")
	check(t, `[]`)
}
