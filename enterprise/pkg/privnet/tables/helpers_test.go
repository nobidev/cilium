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
