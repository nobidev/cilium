//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package bgp

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testDataDir           = "testdata"
	inputFileSuffix       = "-input.yaml"
	goldenFileSuffix      = "-output.yaml"
	unsupportedFilePrefix = "unsupported-"
)

// Tests rendering BGPv1 to BGPv2 APIs by comparing the generated output from input files with golden files.
// You can run 'UPDATE_TESTDATA=1 go test .' to automatically update golden files in testdata/ to the new expected values.
func TestRenderBGPv2API(t *testing.T) {
	// list all input files in testdata subdir
	inputFiles, err := filepath.Glob(filepath.Join(testDataDir, "*"+inputFileSuffix))
	assert.NoError(t, err)

	// run a test per each input file
	for _, inputFile := range inputFiles {
		_, fileName := filepath.Split(inputFile)
		testName, _ := strings.CutSuffix(fileName, inputFileSuffix)

		t.Run(testName, func(t *testing.T) {
			goldenFile := filepath.Join(testDataDir, testName+goldenFileSuffix)
			buffer := bytes.Buffer{}

			err := renderBGPv2APIFromYamlFile(inputFile, &buffer)

			if strings.HasPrefix(testName, unsupportedFilePrefix) {
				// expect unsupported mapping error
				assert.ErrorIs(t, err, errBGPv2MappingUnsupported)
				return
			}
			assert.NoError(t, err)

			if os.Getenv("UPDATE_TESTDATA") != "" {
				// write the golden file to the testdata dir
				err = os.WriteFile(goldenFile, buffer.Bytes(), 0644)
				assert.NoError(t, err)
			} else {
				// compare result with the golden file
				goldenData, err := os.ReadFile(goldenFile)
				assert.NoError(t, err)
				assert.YAMLEq(t, string(goldenData), buffer.String())
			}
		})
	}
}
