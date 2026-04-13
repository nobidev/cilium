// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// ResourceWatcher watches and retrieves new versions of resources from a
// resource set.
// ResourceWatcher implements ResourceVersionObserver to get notified when new
// resource versions are available in the set.
type ResourceWatcher struct {
	logger *slog.Logger

	// typeURL is the URL that uniquely identifies the resource type.
	typeURL string

	// resourceSet is the set of resources to watch.
	resourceSet ResourceSource

	// version is the current version of the resources. Updated in calls to
	// NotifyNewVersion.
	// Versioning starts at 1.
	version uint64

	// versionLocker is used to lock all accesses to version.
	versionLocker lock.Mutex

	// versionCond is a condition that is broadcast whenever the source's
	// current version is increased.
	// versionCond is associated with versionLocker.
	versionCond *sync.Cond
}

// NewResourceWatcher creates a new ResourceWatcher backed by the given
// resource set.
func NewResourceWatcher(logger *slog.Logger, typeURL string, resourceSet ResourceSource) *ResourceWatcher {
	w := &ResourceWatcher{
		logger:      logger,
		version:     1,
		typeURL:     typeURL,
		resourceSet: resourceSet,
	}
	w.versionCond = sync.NewCond(&w.versionLocker)
	return w
}

func (w *ResourceWatcher) HandleNewResourceVersion(typeURL string, version uint64) {
	w.versionLocker.Lock()
	defer w.versionLocker.Unlock()

	if typeURL != w.typeURL {
		return
	}

	if version < w.version {
		logging.Fatal(w.logger,
			"decreasing version number found for resources: xdsCachedVersion < resourceWatcherVersion",
			logfields.XDSCachedVersion, version,
			logfields.ResourceWatcherVersion, w.version,
			logfields.XDSTypeURL, typeURL,
		)
	}
	w.version = version

	w.versionCond.Broadcast()
}

// WatchResourcesSotW watches for new versions of specific resources and sends
// them into the given out channel.
//
// A call to this method blocks until a version greater than lastReceivedVersion is
// available. Therefore, every call must be done in a separate goroutine.
// A watch can be canceled by canceling the given context.
//
// lastAckedVersion is the last version successfully applied by the
// client; zero if this is the first request for resources.
// interestExpanded indicates that the tracked request expanded and therefore needs
// one immediate snapshot before waiting for a newer cache version.
// This method call must always close the out channel.
func (w *ResourceWatcher) WatchResourcesSotW(ctx context.Context, typeURL string, lastReceivedVersion, lastAckedVersion uint64,
	resourceNames []string, interestExpanded bool, out chan<- *VersionedResources) {
	defer close(out)

	scopedLog := w.logger.With(
		logfields.XDSAckedVersion, lastReceivedVersion,
		logfields.XDSTypeURL, typeURL,
	)

	var res *VersionedResources

	waitVersion := lastReceivedVersion
	waitForVersion := !interestExpanded && lastReceivedVersion != 0

	queryVersion := uint64(0)
	if waitForVersion {
		queryVersion = lastReceivedVersion
	}

	for ctx.Err() == nil && res == nil {
		w.versionLocker.Lock()
		// lastReceivedVersion == 0 indicates that this is a new stream and
		// lastAckedVersion comes from previous instance of xDS client.
		// In this case, we artificially increase the version of the resource set
		// to trigger sending a new version to the client.
		if w.version <= lastAckedVersion && lastReceivedVersion == 0 {
			w.versionLocker.Unlock()
			// Calling EnsureVersion will increase the version of the resource
			// set, which in turn will callback w.HandleNewResourceVersion with
			// that new version number. In order for that callback to not
			// deadlock, temporarily unlock w.versionLocker.
			// The w.HandleNewResourceVersion callback will update w.version to
			// the new resource set version.
			w.resourceSet.EnsureVersion(typeURL, lastAckedVersion+1)
			w.versionLocker.Lock()
		}
		if interestExpanded && w.version <= lastReceivedVersion {
			w.versionLocker.Unlock()
			// When the requested resource set expands without any underlying cache
			// update, bump the resource-set version once so the immediate response
			// carries a fresh nonce/version for its different resource contents.
			w.resourceSet.EnsureVersion(typeURL, lastReceivedVersion+1)
			w.versionLocker.Lock()
		}

		// Re-check w.version, since it may have been modified by calling
		// EnsureVersion above.
		for ctx.Err() == nil && waitForVersion && w.version <= waitVersion {
			scopedLog.Debug("waiting for current version to increase up to waitVersion",
				logfields.WaitVersion, waitVersion,
				logfields.CurrentVersion, w.version,
			)
			w.versionCond.Wait()
		}
		// In case we need to loop again, wait for any version more recent than
		// the current one.
		waitForVersion = true
		waitVersion = w.version
		w.versionLocker.Unlock()

		if ctx.Err() != nil {
			break
		}

		scopedLog.Debug("getting resources from set",
			logfields.Resources, len(resourceNames),
		)

		res = w.resourceSet.GetResources(typeURL, queryVersion, resourceNames)
	}

	if res != nil {
		// Resources have changed since the last version returned to the
		// client. Send out the new version.
		select {
		case <-ctx.Done():
		case out <- res:
			return
		}
	}

	err := ctx.Err()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			scopedLog.Debug("context canceled, terminating resource watch")
		} else {
			scopedLog.Error("context error, terminating resource watch", logfields.Error, err)
		}
	}
}

// WatchResourcesDelta watches for delta xDS changes for the tracked
// subscriptions and sends them into the given out channel.
//
// immediate indicates whether the current request changed the tracked set and
// therefore needs an immediate diff before waiting for a newer cache version.
// This method call must always close the out channel.
func (w *ResourceWatcher) WatchResourcesDelta(ctx context.Context, typeURL string, lastReceivedVersion, lastAckedVersion uint64,
	subscriptions []string, ackedResourceNames map[string]struct{}, forceResponseNames []string, immediate bool, out chan<- *VersionedResources) {
	defer close(out)

	scopedLog := w.logger.With(
		logfields.XDSAckedVersion, lastReceivedVersion,
		logfields.XDSTypeURL, typeURL,
	)

	var res *VersionedResources
	waitForVersion := !immediate && lastReceivedVersion != 0
	waitVersion := lastReceivedVersion

	for ctx.Err() == nil && res == nil {
		w.versionLocker.Lock()
		for ctx.Err() == nil && waitForVersion && w.version <= waitVersion {
			scopedLog.Debug("waiting for current version to increase up to waitVersion",
				logfields.WaitVersion, waitVersion,
				logfields.CurrentVersion, w.version,
			)
			w.versionCond.Wait()
		}
		waitForVersion = true
		waitVersion = w.version
		w.versionLocker.Unlock()

		if ctx.Err() != nil {
			break
		}

		scopedLog.Debug("getting delta resources from set",
			logfields.Resources, len(subscriptions),
		)
		res = w.resourceSet.GetDeltaResources(typeURL, lastAckedVersion, subscriptions, ackedResourceNames, forceResponseNames)
		// no point forcing response names if the first round gets nothing
		forceResponseNames = nil
	}

	if res != nil {
		select {
		case <-ctx.Done():
		case out <- res:
			return
		}
	}

	err := ctx.Err()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			scopedLog.Debug("context canceled, terminating resource watch")
		} else {
			scopedLog.Error("context error, terminating resource watch", logfields.Error, err)
		}
	}
}
