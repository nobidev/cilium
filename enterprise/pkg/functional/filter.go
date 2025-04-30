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
)

// Map takes a iterator and when run applies a mapping function from InputType to OutputType
// and returns an iterator that will make the input elements of it to the output elements of OutType.
func Map[InputType, OutType any](it iter.Seq[InputType], fn func(InputType) OutType) iter.Seq[OutType] {
	return func(yield func(OutType) bool) {
		for o := range it {
			if !yield(fn(o)) {
				return
			}
		}
	}
}

// Filter takes a iterator and when run applies one or more filter predicate functions.
// If fn(element) == false then the element is excluded from the output iterator.
func Filter[T any](it iter.Seq[T], fns ...func(T) bool) iter.Seq[T] {
	return func(yield func(T) bool) {
	items:
		for o := range it {
			for _, fn := range fns {
				if !fn(o) {
					continue items
				}
			}
			if !yield(o) {
				return
			}

		}
	}
}

// Not takes a predicate function and returns the functions complement.
func Not[T any](fn func(T) bool) func(T) bool {
	return func(t T) bool {
		return !fn(t)
	}
}
