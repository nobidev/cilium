//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package checker

import (
	"context"
	"slices"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/require"
)

func Wrapped(do func(*testing.T, context.Context)) func(t *testing.T) {
	return func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		do(t, ctx)

		// It should not be strictly required, because ending the function
		// already cancels the context, but the race detector is complaining
		// about an arguably unrelated race for the logger, so here it is...
		cancel()
		synctest.Wait()
	}
}

func Get[T any](t *testing.T, ch <-chan T) (got T) {
	t.Helper()

	synctest.Wait()
	select {
	case got = <-ch:
	default:
		require.FailNow(t, "Expected transition to be observed")
	}
	return got
}

func Expect[T comparable](t *testing.T, ch <-chan T, expected ...T) {
	t.Helper()

	for len(expected) > 0 {
		actual := Get(t, ch)
		require.Contains(t, expected, actual)
		expected = slices.DeleteFunc(expected, func(el T) bool { return el == actual })
	}
}

func NoExpect[T any](t *testing.T, ch <-chan T) {
	t.Helper()

	synctest.Wait()
	select {
	case <-ch:
		require.FailNow(t, "No transition should have been observed")
	default:
	}
}
