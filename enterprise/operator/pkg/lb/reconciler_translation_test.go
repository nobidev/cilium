//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package lb

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8syaml "sigs.k8s.io/yaml"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalentv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

type testcase struct {
	name      string
	t2NodeIPs []string
}

func TestTranslation(t *testing.T) {
	entries, err := os.ReadDir("./testdata/translation")
	require.NoError(t, err)

	testCases := []testcase{}

	for _, d := range entries {
		if !d.IsDir() {
			continue
		}

		testCases = append(testCases, testcase{
			name:      d.Name(),
			t2NodeIPs: []string{"172.18.0.3", "172.18.0.2"}, // TODO: define nodes as YAML?
		})

	}

	for _, tc := range testCases {
		t.Run(tc.name, testTranslationSingle(tc))
	}
}

func testTranslationSingle(tc testcase) func(t *testing.T) {
	return func(t *testing.T) {
		// read input files
		inputLBFrontend := &isovalentv1alpha1.LBFrontend{}
		readInputCR(t, fmt.Sprintf("./testdata/translation/%s/input-lbfrontend.yaml", tc.name), inputLBFrontend)

		var inputService *corev1.Service
		if _, err := os.Stat(fmt.Sprintf("./testdata/translation/%s/input-t1-service.yaml", tc.name)); err == nil {
			inputService = &corev1.Service{}
			readInputCR(t, fmt.Sprintf("./testdata/translation/%s/input-t1-service.yaml", tc.name), inputService)
		}

		// read output files
		expectedServiceYaml := readOutput(t, fmt.Sprintf("./testdata/translation/%s/output-t1-service.yaml", tc.name), &corev1.Service{})
		expectedEndpointsYaml := readOutput(t, fmt.Sprintf("./testdata/translation/%s/output-t1-endpoints.yaml", tc.name), &corev1.Endpoints{})
		expectedCiliumEnvoyConfigYaml := readOutput(t, fmt.Sprintf("./testdata/translation/%s/output-t2-ciliumenvoyconfig.yaml", tc.name), &ciliumv2.CiliumEnvoyConfig{})

		// ingestion
		ing := &ingestor{}

		model, err := ing.ingest(inputLBFrontend, inputService)
		require.NoError(t, err)

		// translation
		reconciler := &standaloneLbReconciler{}

		// T1 Service
		service := reconciler.desiredService(model)
		service.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "Service"} // fix missing typemeta

		actualServiceYaml := toYaml(t, service)
		assert.Equal(t, expectedServiceYaml, actualServiceYaml)

		// T1 Endpoints
		endpoints, err := reconciler.desiredEndpoints(model, tc.t2NodeIPs)
		require.NoError(t, err)
		endpoints.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "Endpoints"} // fix missing typemeta

		actualEndpointsYaml := toYaml(t, endpoints)
		assert.Equal(t, expectedEndpointsYaml, actualEndpointsYaml)

		// T2 CiliumEnvoyConfig
		cec, err := reconciler.desiredCiliumEnvoyConfig(model)
		require.NoError(t, err)

		if cec != nil {
			cec.TypeMeta = metav1.TypeMeta{APIVersion: "cilium.io/v2", Kind: "CiliumEnvoyConfig"} // fix missing typemeta
		}

		actualCiliumEnvoyConfigYaml := ""
		if cec != nil {
			actualCiliumEnvoyConfigYaml = toYaml(t, cec)
		}

		assert.Equal(t, expectedCiliumEnvoyConfigYaml, actualCiliumEnvoyConfigYaml)
	}
}

func readInputCR(t *testing.T, file string, obj any) {
	inputYaml, err := os.ReadFile(file)
	require.NoError(t, err)

	require.NoError(t, k8syaml.Unmarshal(inputYaml, obj))
}

func readOutput(t *testing.T, file string, obj any) string {
	// unmarshal and marshal to prevent forrmatting diffs

	outputYaml, err := os.ReadFile(file)
	require.NoError(t, err)

	if strings.TrimSpace(string(outputYaml)) == "" {
		return strings.TrimSpace(string(outputYaml))
	}

	require.NoError(t, k8syaml.Unmarshal(outputYaml, obj))

	yamlText := toYaml(t, obj)

	return strings.TrimSpace(string(yamlText))
}

func toYaml(t *testing.T, obj any) string {
	yamlText, err := k8syaml.Marshal(obj)
	require.NoError(t, err)

	return strings.TrimSpace(string(yamlText))
}
