// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

type selectorObserver struct {
	updateMutex lock.Mutex
	updateCond  *sync.Cond

	updates []SelectorUpdates

	blockEntered chan struct{}
	blockRelease chan struct{}
}

func newSelectorObserver() *selectorObserver {
	so := &selectorObserver{}
	so.updateCond = sync.NewCond(&so.updateMutex)
	return so
}

func cloneSelectorCacheUpdate(update SelectorUpdates) SelectorUpdates {
	cloned := SelectorUpdates{
		Revision: update.Revision,
		Changes:  make([]SelectorChange, len(update.Changes)),
	}
	for i, change := range update.Changes {
		cloned.Changes[i] = SelectorChange{
			ID:         change.ID,
			Removed:    change.Removed,
			Selections: slices.Clone(change.Selections),
		}
	}
	return cloned
}

func cloneSelectorSnapshot(snapshot SelectorSnapshot) map[types.SelectorId]identity.NumericIdentitySlice {
	cloned := make(map[types.SelectorId]identity.NumericIdentitySlice)
	for id, selections := range snapshot.All() {
		cloned[id] = slices.Clone(selections)
	}
	return cloned
}

func (so *selectorObserver) SelectorCacheUpdated(update SelectorUpdates) {
	so.updateMutex.Lock()
	entered := so.blockEntered
	release := so.blockRelease
	so.blockEntered = nil
	so.blockRelease = nil
	so.updateMutex.Unlock()

	if entered != nil {
		close(entered)
		<-release
	}

	so.updateMutex.Lock()
	so.updates = append(so.updates, cloneSelectorCacheUpdate(update))
	so.updateCond.Broadcast()
	so.updateMutex.Unlock()
}

func (so *selectorObserver) waitForCount(n int) []SelectorUpdates {
	so.updateMutex.Lock()
	defer so.updateMutex.Unlock()
	for len(so.updates) < n {
		so.updateCond.Wait()
	}
	return slices.Clone(so.updates)
}

func (so *selectorObserver) blockNext() (<-chan struct{}, chan<- struct{}) {
	entered := make(chan struct{})
	release := make(chan struct{})

	so.updateMutex.Lock()
	so.blockEntered = entered
	so.blockRelease = release
	so.updateMutex.Unlock()

	return entered, release
}

func TestSelectorCacheObserverInitialAndLiveUpdate(t *testing.T) {
	logger := hivetest.Logger(t)
	sc := testNewSelectorCache(t, logger, nil)
	user := newUser(t, "user", sc)

	selector := user.AddIdentitySelector(api.NewESFromLabels(labels.ParseSelectLabel("k8s:id=a")))
	observer := newSelectorObserver()
	snapshot, unregister := sc.RegisterSelectorCacheObserver(observer)
	t.Cleanup(unregister)
	t.Cleanup(func() { snapshot.Invalidate() })

	initial := cloneSelectorSnapshot(snapshot)
	require.Contains(t, initial, selector.Id())
	require.Empty(t, initial[selector.Id()])

	wg := &sync.WaitGroup{}
	sc.UpdateIdentities(identity.IdentityMap{
		1001: labels.LabelArray{labels.NewLabel("id", "a", labels.LabelSourceK8s)},
	}, nil, wg)
	wg.Wait()

	updates := observer.waitForCount(1)
	require.Len(t, updates[0].Changes, 1)
	require.Equal(t, selector.Id(), updates[0].Changes[0].ID)
	require.Equal(t, identity.NumericIdentitySlice{1001}, updates[0].Changes[0].Selections)
	require.Greater(t, updates[0].Revision, snapshot.Revision)
}

func TestSelectorCacheObserverWaitGroupAfterObserverCallback(t *testing.T) {
	logger := hivetest.Logger(t)
	sc := testNewSelectorCache(t, logger, nil)
	user := newUser(t, "user", sc)

	user.AddIdentitySelector(api.NewESFromLabels(labels.ParseSelectLabel("k8s:id=a")))
	observer := newSelectorObserver()
	snapshot, unregister := sc.RegisterSelectorCacheObserver(observer)
	t.Cleanup(unregister)
	t.Cleanup(func() { snapshot.Invalidate() })

	entered, release := observer.blockNext()
	wg := &sync.WaitGroup{}
	sc.UpdateIdentities(identity.IdentityMap{
		1001: labels.LabelArray{labels.NewLabel("id", "a", labels.LabelSourceK8s)},
	}, nil, wg)

	<-entered
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("selector observer waitgroup completed before callback returned")
	default:
	}

	returned := make(chan struct{})
	secondWG := &sync.WaitGroup{}
	go func() {
		sc.UpdateIdentities(identity.IdentityMap{
			1002: labels.LabelArray{labels.NewLabel("id", "a", labels.LabelSourceK8s)},
		}, nil, secondWG)
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("second selector update blocked behind observer callback")
	}

	close(release)
	wg.Wait()
	secondWG.Wait()
	observer.waitForCount(2)
}

func TestSelectorCacheObserverMutationPublishesFullSelections(t *testing.T) {
	logger := hivetest.Logger(t)
	sc := testNewSelectorCache(t, logger, identity.IdentityMap{
		1001: labels.LabelArray{labels.NewLabel("id", "a", labels.LabelSourceK8s)},
	})
	user := newUser(t, "user", sc)

	fooSelector := user.AddIdentitySelector(api.NewESFromLabels(labels.ParseSelectLabel("k8s:id=a")))
	barSelector := user.AddIdentitySelector(api.NewESFromLabels(labels.ParseSelectLabel("k8s:id=b")))
	observer := newSelectorObserver()
	snapshot, unregister := sc.RegisterSelectorCacheObserver(observer)
	t.Cleanup(unregister)
	t.Cleanup(func() { snapshot.Invalidate() })

	initial := cloneSelectorSnapshot(snapshot)
	require.Equal(t, identity.NumericIdentitySlice{1001}, initial[fooSelector.Id()])
	require.Empty(t, initial[barSelector.Id()])

	wg := &sync.WaitGroup{}
	sc.UpdateIdentities(identity.IdentityMap{
		1001: labels.LabelArray{labels.NewLabel("id", "b", labels.LabelSourceK8s)},
	}, nil, wg)
	wg.Wait()

	updates := observer.waitForCount(1)
	require.Len(t, updates[0].Changes, 2)

	changesByID := make(map[types.SelectorId]SelectorChange, len(updates[0].Changes))
	for _, change := range updates[0].Changes {
		changesByID[change.ID] = change
	}

	require.Empty(t, changesByID[fooSelector.Id()].Selections)
	require.Equal(t, identity.NumericIdentitySlice{1001}, changesByID[barSelector.Id()].Selections)
}

func TestSelectorCacheObserverEmptyCommitUpdate(t *testing.T) {
	logger := hivetest.Logger(t)
	sc := testNewSelectorCache(t, logger, nil)
	observer := newSelectorObserver()
	snapshot, unregister := sc.RegisterSelectorCacheObserver(observer)
	t.Cleanup(unregister)
	t.Cleanup(func() { snapshot.Invalidate() })

	sc.Commit()

	updates := observer.waitForCount(1)
	require.Equal(t, snapshot.Revision+1, updates[0].Revision)
	require.Empty(t, updates[0].Changes)
}
