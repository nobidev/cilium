/*
Copyright (C) Isovalent, Inc. - All Rights Reserved.

NOTICE: All information contained herein is, and remains the property of
Isovalent Inc and its suppliers, if any. The intellectual and technical
concepts contained herein are proprietary to Isovalent Inc and its suppliers
and may be covered by U.S. and Foreign Patents, patents in process, and are
protected by trade secret or copyright law.  Dissemination of this information
or reproduction of this material is strictly forbidden unless prior written
permission is obtained from Isovalent Inc.
*/

package helm

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	// "sigs.k8s.io/e2e-framework/klient/k8s"
)

type resHandlerFunc func(*unstructured.Unstructured)

// Decode processes a stream of documents of any Kind and returns them as unstructured objects.
func Decode(manifests io.Reader) ([]*unstructured.Unstructured, error) {
	objects := []*unstructured.Unstructured{}
	handlerFn := func(obj *unstructured.Unstructured) {
		objects = append(objects, obj)
	}
	if err := DecodeEach(manifests, handlerFn); err != nil {
		return nil, fmt.Errorf("failed to process helm charts: %w", err)
	}
	return objects, nil
}

// DecodeEach decodes a stream of documents of any Kind and returns them as unstructured objects.
func DecodeEach(manifests io.Reader, handlerFn resHandlerFunc) error {
	decoder := yaml.NewYAMLReader(bufio.NewReader(manifests))
	for {
		b, err := decoder.Read()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return err
		}
		obj, err := DecodeAny(bytes.NewReader(b))
		if err != nil {
			// Skip the Missing Kind entries. This will avoid unwanted failures of the yaml apply workflow when
			// the file has an empty item with just comments in it.
			if runtime.IsMissingKind(err) {
				continue
			}
			return err
		}
		handlerFn(obj)
	}
	return nil
}

// DecodeAny decodes any single-document YAML or JSON input and returns it as unstructured.Unstructured.
func DecodeAny(manifest io.Reader) (*unstructured.Unstructured, error) {
	b, err := io.ReadAll(manifest)
	if err != nil {
		return nil, err
	}
	u := &unstructured.Unstructured{}
	if err := yaml.Unmarshal(b, u); err != nil {
		return nil, err
	}
	return u, nil
}
