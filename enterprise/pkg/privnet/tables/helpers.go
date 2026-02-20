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
