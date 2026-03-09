// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tables

import (
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/time"
)

func formatActivatedAt(activatedAt time.Time) string {
	if activatedAt.IsZero() {
		return "<inactive>"
	}
	return activatedAt.UTC().Format(time.RFC3339)
}

// equalElements compares two slices and returns if they contain the same elements.
// NOTE: It will *ignore* duplicates in the slice
func equalElements[T comparable](a, b []T) bool {
	sa := sets.New(a...)
	sb := sets.New(b...)
	return sa.Equal(sb)
}

// Selector wraps a [labels.Selector] so that it can be pretty-printed when
// outputting the statedb table in json/yaml format.
type Selector struct{ labels.Selector }

func (sel Selector) String() string {
	if _, selectable := sel.Selector.Requirements(); !selectable {
		return "<nothing>"
	}

	return sel.Selector.String()
}

// MarshalText implements the [encoding.TextMarshaler] interface.
func (sel Selector) MarshalText() ([]byte, error) {
	return []byte(sel.String()), nil
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (sel *Selector) UnmarshalText(in []byte) (err error) {
	if string(in) == "<nothing>" {
		sel.Selector = labels.Nothing()
	} else {
		sel.Selector, err = labels.Parse(string(in))
	}

	return err
}
