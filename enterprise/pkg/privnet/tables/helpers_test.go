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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
)

func TestEqualElements(t *testing.T) {
	for _, tc := range []struct {
		name  string
		a, b  []int
		equal bool
	}{
		{
			name:  "empty",
			a:     []int{},
			b:     []int{},
			equal: true,
		},
		{
			name:  "nil",
			a:     nil,
			b:     nil,
			equal: true,
		},
		{
			name:  "nil/empty",
			a:     nil,
			b:     []int{},
			equal: true,
		},
		{
			name:  "one empty",
			a:     []int{},
			b:     []int{1, 2, 3},
			equal: false,
		},
		{
			name:  "one nil",
			a:     []int{1, 4},
			b:     nil,
			equal: false,
		},
		{
			name:  "same",
			a:     []int{1, 2, 3, 4, 6},
			b:     []int{1, 2, 3, 4, 6},
			equal: true,
		},
		{
			name:  "same reordered",
			a:     []int{1, 4, 6, 3, 2},
			b:     []int{1, 2, 3, 4, 6},
			equal: true,
		},
		{
			name:  "same duplicates",
			a:     []int{1, 4, 6, 3, 6, 2, 2},
			b:     []int{1, 2, 3, 4, 6, 4},
			equal: true,
		},
		{
			name:  "different",
			a:     []int{1, 5, 6, 3, 2},
			b:     []int{1, 2, 3, 4, 6},
			equal: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.equal, equalElements(tc.a, tc.b))
		})
	}
}

func TestSelectorRoudtripping(t *testing.T) {
	tests := []struct {
		name     string
		selector Selector
		expected string
	}{
		{
			name:     "everything",
			selector: Selector{labels.Everything()},
			expected: "",
		},
		{
			name:     "nothing",
			selector: Selector{labels.Nothing()},
			expected: "<nothing>",
		},
		{
			name: "selector",
			selector: func() Selector {
				sel, err := labels.Parse("foo=bar,qux notin (fred,qux)")
				require.NoError(t, err, "labels.Parse")
				return Selector{sel}
			}(),
			expected: "foo=bar,qux notin (fred,qux)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, tt.selector.String(), "Selector.String")

			fwd, err := tt.selector.MarshalText()
			require.NoError(t, err, "Selector.MarshalText")
			require.Equal(t, tt.expected, string(fwd), "Selector.MarshalText")

			var bwd Selector
			require.NoError(t, bwd.UnmarshalText(fwd), "Selector.UnmarshalText")

			// We don't compare for pure equality, as the same selector may otherwise
			// be flagged as different due to different underlying representation.
			req, sel := tt.selector.Requirements()
			breq, bsel := bwd.Requirements()

			require.ElementsMatch(t, req, breq, "Requirements")
			require.Equal(t, sel, bsel, "Selectable")
		})
	}
}
