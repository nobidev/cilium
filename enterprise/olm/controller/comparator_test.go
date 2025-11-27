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

package controller

import (
	"strings"
	"testing"

	"github.com/isovalent/cilium/enterprise/olm/helm"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var deployment = `
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cilium-operator
  namespace: cilium
  labels:
    io.cilium/app: operator
    name: cilium-operator
    app.kubernetes.io/part-of: cilium
    app.kubernetes.io/name: cilium-operator
    isovalent.io/managed-by: clife
    app.kubernetes.io/version: 0.0.2
spec:
  # See docs on ServerCapabilities.LeasesResourceLock in file pkg/k8s/version/version.go
  # for more details.
  replicas: 2
  selector:
    matchLabels:
      io.cilium/app: operator
      name: cilium-operator
  # ensure operator update on single node k8s clusters, by using rolling update with maxUnavailable=100% in case
  # of one replica and no user configured Recreate strategy.
  # otherwise an update might get stuck due to the default maxUnavailable=50% in combination with the
  # podAntiAffinity which prevents deployments of multiple operator replicas on the same node.
  strategy:
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 100%
    type: RollingUpdate
  template:
    metadata:
      labels:
        io.cilium/app: operator
        name: cilium-operator
        app.kubernetes.io/part-of: cilium
        app.kubernetes.io/name: cilium-operator
    spec:
      containers:
      - name: cilium-operator
        image: quay.io/isovalent-dev/operator:latest
        imagePullPolicy: Always
        command:
        - cilium-operator
        args:
        - --config-dir=/tmp/cilium/config-map
        env:
        - name: K8S_NODE_NAME
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: spec.nodeName`

var secret = `
---
apiVersion: v1
kind: Secret
metadata:
  name: hubble-relay-server-certs
  namespace: cilium
  labels:
    isovalent.io/managed-by: clife
    app.kubernetes.io/version: 0.0.2
type: kubernetes.io/tls
data:
  ca.crt:  aGlwIQo=
  tls.crt: aG9wIQo=
  tls.key: aGVwIQo=
`

var nonIdempotentSecret = `
---
apiVersion: v1
kind: Secret
metadata:
  name: hubble-relay-server-certs
  namespace: cilium
  labels:
    isovalent.io/managed-by: clife
    app.kubernetes.io/version: 0.0.2
    cilium.io/helm-template-non-idempotent: "true"
type: kubernetes.io/tls
data:
  ca.crt:  aGlwIQo=
  tls.crt: aG9wIQo=
  tls.key: aGVwIQo=
`

func TestDiff(t *testing.T) {
	dstr := strings.NewReader(deployment)
	depl, err := helm.Decode(dstr)
	require.NoError(t, err, "expect no error decoding deployment")
	sstr := strings.NewReader(secret)
	sec, err := helm.Decode(sstr)
	require.NoError(t, err, "expect no error decoding secret")
	nisstr := strings.NewReader(nonIdempotentSecret)
	nisec, err := helm.Decode(nisstr)
	require.NoError(t, err, "expect no error decoding non-idempotent secret")
	var desired []*unstructured.Unstructured
	var current map[string]*unstructured.Unstructured
	var a, r []*unstructured.Unstructured
	var newLabels map[string]string
	// Test that a missing deployment is created
	desired = depl
	current = map[string]*unstructured.Unstructured{}
	a, r = Diff(desired, current)
	require.Len(t, a, 1, "expect one resource to be applied")
	require.Contains(t, a, depl[0])
	require.Empty(t, r, "expect no resource to be removed")

	// Test that changes to deployments are applied
	desired = depl
	current = map[string]*unstructured.Unstructured{}
	current["Deployment/cilium/cilium-operator"] = depl[0].DeepCopy()
	newLabels = current["Deployment/cilium/cilium-operator"].GetLabels()
	newLabels["app.kubernetes.io/part-of"] = "cilium-revival"
	current["Deployment/cilium/cilium-operator"].SetLabels(newLabels)
	a, r = Diff(desired, current)
	require.Len(t, a, 1, "expect one resource to be applied")
	require.Contains(t, a, depl[0], "expect the desired deployment to be applied")
	require.Empty(t, r, "expect no resource to be removed")

	// Test that changes to non-idempotent secrets are not applied when the version does not change
	desired = nisec
	current = map[string]*unstructured.Unstructured{}
	current["Secret/cilium/hubble-relay-server-certs"] = nisec[0].DeepCopy()
	newLabels = current["Secret/cilium/hubble-relay-server-certs"].GetLabels()
	newLabels["app.kubernetes.io/part-of"] = "cilium-revival"
	current["Secret/cilium/hubble-relay-server-certs"].SetLabels(newLabels)
	a, r = Diff(desired, current)
	require.Len(t, a, 0, "expect the secret not to be applied")
	require.Empty(t, r, "expect no resource to be removed")

	// Test that changes to non-idempotent secrets are applied when the version changes
	desired = nisec
	current = map[string]*unstructured.Unstructured{}
	current["Secret/cilium/hubble-relay-server-certs"] = nisec[0].DeepCopy()
	newLabels = current["Secret/cilium/hubble-relay-server-certs"].GetLabels()
	newLabels["app.kubernetes.io/part-of"] = "cilium-revival"
	newLabels[VersionLabelKey] = "0.0.1"
	current["Secret/cilium/hubble-relay-server-certs"].SetLabels(newLabels)
	a, r = Diff(desired, current)
	require.Len(t, a, 1, "expect the secret to be applied")
	require.Empty(t, r, "expect no resource to be removed")

	// Test that changes to idempotent secrets are applied when the version does not change
	desired = sec
	current = map[string]*unstructured.Unstructured{}
	current["Secret/cilium/hubble-relay-server-certs"] = sec[0].DeepCopy()
	newLabels = current["Secret/cilium/hubble-relay-server-certs"].GetLabels()
	newLabels["app.kubernetes.io/part-of"] = "cilium-revival"
	current["Secret/cilium/hubble-relay-server-certs"].SetLabels(newLabels)
	a, r = Diff(desired, current)
	require.Len(t, a, 1, "expect the secret to be applied")
	require.Empty(t, r, "expect no resource to be removed")

	// Test that missing resources are applied
	desired = append(depl, sec...)
	current = map[string]*unstructured.Unstructured{}
	current["Deployment/cilium/cilium-operator"] = depl[0]
	a, r = Diff(desired, current)
	require.Len(t, a, 2, "expect two resources to be applied")
	require.Empty(t, r, "expect no resource to be removed")

	// Test that resources not desired are removed
	desired = depl
	current = map[string]*unstructured.Unstructured{}
	current["Deployment/cilium/cilium-operator"] = depl[0]
	current["Secret/cilium/hubble-relay-server-certs"] = sec[0]
	a, r = Diff(desired, current)
	require.Len(t, a, 1, "expect one resource to be applied")
	require.Len(t, r, 1, "expect one resource to be removed")
	require.Contains(t, r, sec[0], "expect the secret not desired to be removed")
}

func TestIsNonIdempotent(t *testing.T) {
	sstr := strings.NewReader(secret)
	sec, err := helm.Decode(sstr)
	require.NoError(t, err, "expect no error decoding secret")
	require.False(t, isNonIdempotent(sec[0]))
	nisstr := strings.NewReader(nonIdempotentSecret)
	nisec, err := helm.Decode(nisstr)
	require.NoError(t, err, "expect no error decoding secret")
	require.True(t, isNonIdempotent(nisec[0]))
}

func TestHasChangedVersion(t *testing.T) {
	sstr := strings.NewReader(secret)
	sec, err := helm.Decode(sstr)
	require.NoError(t, err, "expect no error decoding secret")
	newSec := sec[0].DeepCopy()
	require.False(t, hasChangedVersion(newSec, sec[0]))
	nls := newSec.GetLabels()
	nls[VersionLabelKey] = "0.0.3"
	newSec.SetLabels(nls)
	require.True(t, hasChangedVersion(newSec, sec[0]))
	newSec.SetLabels(nil)
	require.True(t, hasChangedVersion(newSec, sec[0]))
}
