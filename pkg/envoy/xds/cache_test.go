// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"maps"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/google/go-cmp/cmp"
)

func versionedResourceNames(resources []VersionedResource) []string {
	names := make([]string, 0, len(resources))
	for _, vr := range resources {
		names = append(names, vr.Name)
	}
	slices.Sort(names)
	names = slices.Compact(names)
	return names
}

func TestGetResourcesSotW(t *testing.T) {
	logger := hivetest.Logger(t)
	c := NewCache(logger)
	c.resources[cacheKey{typeURL: "a", resourceName: "a1"}] = cacheValue{}
	c.resources[cacheKey{typeURL: "a", resourceName: "a2"}] = cacheValue{}
	c.resources[cacheKey{typeURL: "b", resourceName: "a1"}] = cacheValue{}
	c.resources[cacheKey{typeURL: "b", resourceName: "b2"}] = cacheValue{lastModifiedVersion: 1}

	for _, tc := range []struct {
		desc            string
		typeURL         string
		version         uint64
		getNames        []string
		wantNames       []string
		wantNilResponse bool
	}{
		{
			desc:      "return resource by name",
			typeURL:   "a",
			getNames:  []string{"a1"},
			wantNames: []string{"a1"},
		},
		{
			desc:      "return all resources for given url",
			typeURL:   "a",
			wantNames: []string{"a1", "a2"},
		},
		{
			desc:      "no resources found for given url",
			typeURL:   "c",
			wantNames: []string{},
		},
		{
			desc:      "no resources found for given name and url",
			typeURL:   "b",
			getNames:  []string{"c1"},
			wantNames: []string{},
		},
		{
			desc:            "resource has no updates",
			typeURL:         "b",
			version:         1,
			getNames:        []string{"b2"},
			wantNilResponse: true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			got := c.GetResources(tc.typeURL, tc.version, tc.getNames)
			gotNilResponse := got == nil
			if gotNilResponse != tc.wantNilResponse {
				t.Fatalf("Returned response mismatch want: gotNilResponse != tc.wantNilResponse  %v != %v", gotNilResponse, tc.wantNilResponse)
			}
			if got == nil {
				return
			}
			names := versionedResourceNames(got.VersionedResources)
			if diff := cmp.Diff(names, tc.wantNames); diff != "" {
				t.Fatalf("returned resources mismatch (-got/+want): %v", diff)
			}
		})
	}
}

func TestGetDeltaResources(t *testing.T) {
	logger := hivetest.Logger(t)
	c := NewCache(logger)
	c.version = 5
	c.resources[cacheKey{typeURL: "a", resourceName: "a1"}] = cacheValue{lastModifiedVersion: 2}
	c.resources[cacheKey{typeURL: "a", resourceName: "a2"}] = cacheValue{lastModifiedVersion: 5}
	c.resources[cacheKey{typeURL: "a", resourceName: "a3"}] = cacheValue{lastModifiedVersion: 4}

	for _, tc := range []struct {
		desc               string
		subscriptions      []string
		lastAckedVersion   uint64
		ackedResourceNames map[string]struct{}
		forceResponseNames []string
		wantNames          []string
		wantRemoved        []string
		wantNilResponse    bool
	}{
		{
			desc:             "empty subscriptions are wildcard",
			subscriptions:    nil,
			lastAckedVersion: 0,
			wantNames:        []string{"a1", "a2", "a3"},
		},
		{
			desc:             "wildcard returns all newer resources",
			subscriptions:    []string{"*"},
			lastAckedVersion: 0,
			wantNames:        []string{"a1", "a2", "a3"},
		},
		{
			desc:             "wildcard with named subscription still behaves as wildcard",
			subscriptions:    []string{"*", "a1"},
			lastAckedVersion: 0,
			wantNames:        []string{"a1", "a2", "a3"},
		},
		{
			desc:               "force response names resend unchanged resources",
			subscriptions:      []string{"a1"},
			lastAckedVersion:   5,
			forceResponseNames: []string{"a1"},
			wantNames:          []string{"a1"},
		},
		{
			desc:               "force response names resend unchanged resources with wildcard",
			subscriptions:      []string{"*"},
			lastAckedVersion:   5,
			forceResponseNames: []string{"a1"},
			wantNames:          []string{"a1"},
		},
		{
			desc:               "removed names only from still tracked acked names",
			subscriptions:      []string{"a1", "a4"},
			lastAckedVersion:   5,
			ackedResourceNames: map[string]struct{}{"a1": {}, "a3": {}, "a4": {}},
			wantNames:          []string{},
			wantRemoved:        []string{"a4"},
		},
		{
			desc:               "wildcard removals are not filtered by explicit names",
			subscriptions:      []string{"*", "a1"},
			lastAckedVersion:   5,
			ackedResourceNames: map[string]struct{}{"a4": {}},
			wantNames:          []string{},
			wantRemoved:        []string{"a4"},
		},
		{
			desc:               "unsubscribed names do not produce removals",
			subscriptions:      []string{"a1"},
			lastAckedVersion:   5,
			ackedResourceNames: map[string]struct{}{"a2": {}},
			wantNilResponse:    true,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			got := c.GetDeltaResources("a", tc.lastAckedVersion, tc.subscriptions, maps.Clone(tc.ackedResourceNames), tc.forceResponseNames)
			if (got == nil) != tc.wantNilResponse {
				t.Fatalf("GetDeltaResources() nil response mismatch: got %v wantNil %v", got == nil, tc.wantNilResponse)
			}
			if got == nil {
				return
			}
			if diff := cmp.Diff(versionedResourceNames(got.VersionedResources), tc.wantNames); diff != "" {
				t.Fatalf("returned resources mismatch (-got/+want): %s", diff)
			}
			if diff := cmp.Diff(got.RemovedNames, tc.wantRemoved); diff != "" {
				t.Fatalf("returned removed names mismatch (-got/+want): %s", diff)
			}
		})
	}
}
