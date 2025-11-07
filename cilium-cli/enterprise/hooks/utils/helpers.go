// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package utils

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
)

// ParseYAML decodes a YAML file into a slice of objects.
func ParseYAML[T runtime.Object](input string) (output []T, err error) {
	for yaml := range strings.SplitSeq(input, "\n---") {
		if strings.TrimSpace(yaml) == "" {
			continue
		}

		obj, kind, err := serializer.NewCodecFactory(scheme.Scheme, serializer.EnableStrict).UniversalDeserializer().Decode([]byte(yaml), nil, nil)
		if err != nil {
			return nil, fmt.Errorf("decoding yaml file: %s\nerror: %w", yaml, err)
		}

		switch out := obj.(type) {
		case T:
			output = append(output, out)
		default:
			return nil, fmt.Errorf("unknown type '%s' in: %s", kind.Kind, yaml)
		}
	}

	return output, nil
}
