//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package status

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFmtWrapLineItemsTitle(t *testing.T) {

	for _, tc := range []struct {
		name     string
		title    string
		items    []string
		indent   int
		width    int
		expected []string
	}{
		{
			name:     "empty",
			title:    "foo",
			items:    []string{},
			indent:   5,
			width:    30,
			expected: []string{"foo  "},
		},
		{
			name:  "simple",
			title: "foo",
			items: []string{
				"foo1", "foo2", "foo3",
			},
			indent:   5,
			width:    30,
			expected: []string{"foo  foo1  foo2  foo3"},
		},
		{
			name:  "simple indent",
			title: "foo",
			items: []string{
				"foo1", "foo2", "foo3", "foo4",
			},
			indent: 5,
			width:  20,
			expected: []string{
				"foo  foo1  foo2",
				"     foo3  foo4",
			},
		},
		{
			name:  "simple multi indent",
			title: "foo",
			items: []string{
				"foo1", "foo2", "foo3", "foo4", "foo5", "foo6", "foo7", "foo8",
			},
			indent: 5,
			width:  20,
			expected: []string{
				"foo  foo1  foo2",
				"     foo3  foo4",
				"     foo5  foo6",
				"     foo7  foo8",
			},
		},
		{
			name:  "variable length multi indent",
			title: "foo",
			items: []string{
				"foo", "fooo", "foooo", "fooooo", "foooooo", "fooooooo", "fooooooooo", "fooooooooooooooooooo",
			},
			indent: 5,
			width:  25,
			expected: []string{
				"foo  foo  fooo  foooo",
				"     fooooo  foooooo",
				"     fooooooo  fooooooooo",
				"     fooooooooooooooooooo",
			},
		},
		{
			name:  "variable length multi indent - items too long",
			title: "foo",
			items: []string{
				"foo", "fooo", "foooo",
				"fooooo", "foooooo",
				"fooooooooooooooooooo0oooo000ooooooooooooooooooooooooooo0ooooo",
				"fooooooo", "fooooooooo",
				"fooooooooooooooooooo0oooo",
				"bar", "just", "fo",
			},
			indent: 5,
			width:  25,
			expected: []string{
				"foo  foo  fooo  foooo",
				"     fooooo  foooooo",
				"     fooooooooooooooooooo0oooo000ooooooooooooooooooooooooooo0ooooo",
				"     fooooooo  fooooooooo",
				"     fooooooooooooooooooo0oooo",
				"     bar  just  fo",
			},
		},
		{
			name:  "variable length multi indent - first item too long",
			title: "foo",
			items: []string{
				"fooooooooooooooooooo0oooo000ooooooooooooooooooooooooooo0ooooo",
				"bar", "just", "fo",
			},
			indent: 5,
			width:  25,
			expected: []string{
				"foo  fooooooooooooooooooo0oooo000ooooooooooooooooooooooooooo0ooooo",
				"     bar  just  fo",
			},
		},

		{
			name:  "title too long",
			title: "loong",
			items: []string{
				"foo", "fooo", "fooo",
				"bar", "just", "fo",
			},
			indent: 5,
			width:  20,
			expected: []string{
				"loong",
				"     foo  fooo  fooo",
				"     bar  just  fo",
			},
		},

		{
			name:  "title very long",
			title: "This is entirely too long....",
			items: []string{
				"foo", "fooo", "fooo",
				"bar", "just", "fo",
			},
			indent: 5,
			width:  20,
			expected: []string{
				"This is entirely too long....",
				"     foo  fooo  fooo",
				"     bar  just  fo",
			},
		},
	} {

		t.Run(tc.name, func(t *testing.T) {
			expected := strings.Join(tc.expected, "\n") + "\n"
			require.Equal(t, expected, fmtWrapLineItemsTitle(tc.title, tc.items, tc.indent, tc.width))
		})
	}
}

func TestFmtBar(t *testing.T) {
	for _, tc := range []struct {
		name                string
		left, center, right string
		width               int
		expected            string
	}{
		{
			name:     "simple",
			left:     "foo",
			center:   "bar",
			right:    "buzz",
			width:    30,
			expected: "foo           bar         buzz",
		},
		{
			name:     "long left",
			left:     "fooooooooooo",
			center:   "bar",
			right:    "buzz",
			width:    30,
			expected: "fooooooooooo  bar         buzz",
		},
		{
			name:     "long right",
			left:     "foo",
			center:   "bar",
			right:    "buzzzzzzz",
			width:    30,
			expected: "foo           bar    buzzzzzzz",
		},
		{
			name:     "long center",
			left:     "foo",
			center:   "baaaaaaaaaaar",
			right:    "buzz",
			width:    30,
			expected: "foo      baaaaaaaaaaar    buzz",
		},
		{
			name:     "too long",
			left:     "foooooooo",
			center:   "baaaaaaaaaaar",
			right:    "buzzzzzz",
			width:    30,
			expected: "foooooooo baaaaaaaaaaar buzzzzzz",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, FmtReset(tc.expected+"\n"), FmtReset(fmtBar(tc.left, tc.center, tc.right, tc.width)))
		})

	}

}
