//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package functional

import (
	"iter"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

func intRange(n int) iter.Seq[int] {
	return func(yield func(int) bool) {
		for i := range n {
			if !yield(i) {
				return
			}
		}
	}
}

func TestFilter(t *testing.T) {
	type filterTest struct {
		name   string
		fns    []func(n int) bool
		input  iter.Seq[int]
		output []int
	}

	for _, tc := range []filterTest{
		{
			name: "evens",
			fns: []func(n int) bool{
				func(n int) bool {
					return n%2 == 0
				},
			},
			input:  intRange(8),
			output: []int{0, 2, 4, 6},
		},
		{
			name: "odds",
			fns: []func(n int) bool{
				func(n int) bool {
					return n%2 != 0
				},
			},
			input:  intRange(8),
			output: []int{1, 3, 5, 7},
		},
		{
			name: "contradiction",
			fns: []func(n int) bool{
				func(n int) bool {
					return false
				},
			},
			input:  intRange(8),
			output: nil, // according to slices.Collect: if iter is empty slice is nil.
		},
		{
			name: "tautology",
			fns: []func(n int) bool{
				func(n int) bool {
					return true
				},
			},
			input:  intRange(8),
			output: slices.Collect(intRange(8)),
		},
		{
			name: "empty input",
			fns: []func(n int) bool{
				func(n int) bool {
					return true
				},
			},
			input:  intRange(0),
			output: nil, // according to slices.Collect: if iter is empty slice is nil.
		},
		{
			name: "multiple filter fns",
			fns: []func(n int) bool{
				func(n int) bool {
					return true
				},
				func(n int) bool {
					return n >= 70
				},
				func(n int) bool {
					return n <= 75
				},
			},
			input:  intRange(100),
			output: []int{70, 71, 72, 73, 74, 75},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := slices.Collect(Filter(tc.input, tc.fns...))
			assert.Equal(t, tc.output, out)
		})
	}

}
