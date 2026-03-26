// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law. Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"
	"k8s.io/client-go/util/jsonpath"
)

func templateCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "expand a text/template file using the script environment (.Env) and inline key=value arguments (.Args)",
			Args:    "template-file target-file [key=value...]",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 2 {
				return nil, script.ErrUsage
			}

			templatePath := s.Path(args[0])
			targetPath := s.Path(args[1])

			src, err := os.ReadFile(templatePath)
			if err != nil {
				return nil, err
			}

			env := map[string]string{}
			for _, kv := range s.Environ() {
				key, value, found := strings.Cut(kv, "=")
				if found {
					env[key] = value
				}
			}
			argsMap := map[string]string{}
			for _, kv := range args[2:] {
				key, value, found := strings.Cut(kv, "=")
				if !found {
					return nil, fmt.Errorf("expected key=value, got %q", kv)
				}
				argsMap[key] = value
			}

			tmpl, err := template.New(args[0]).Parse(string(src))
			if err != nil {
				return nil, err
			}

			out, err := os.Create(targetPath)
			if err != nil {
				return nil, err
			}
			defer out.Close()

			err = tmpl.Execute(out, struct {
				Env  map[string]string
				Args map[string]string
			}{
				Env:  env,
				Args: argsMap,
			})
			return nil, err
		},
	)
}

func jsonPathCmd() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "prints the output of a jsonpath expression against the input file",
			Args:    "input-file jsonpath-template",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("output", "o", "", "output file name")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 2 {
				return nil, script.ErrUsage
			}

			outFile, err := s.Flags.GetString("output")
			if err != nil {
				return nil, fmt.Errorf("failed get output: %w", err)
			}

			return func(s *script.State) (stdout string, stderr string, err error) {
				inputFile := s.Path(args[0])
				jsonPath := args[1]

				jsonStr, err := os.ReadFile(inputFile)
				if err != nil {
					return stdout, stderr, fmt.Errorf("failed to read file %s: %w", inputFile, err)
				}

				var data any
				if err := json.Unmarshal(jsonStr, &data); err != nil {
					return stdout, stderr, fmt.Errorf("failed to unmarshal JSON: %w", err)
				}

				jp := jsonpath.New("query")
				if err := jp.Parse(jsonPath); err != nil {
					return stdout, stderr, fmt.Errorf("failed to parse jsonpath template: %w", err)
				}

				results, err := jp.FindResults(data)
				if err != nil {
					return stdout, stderr, fmt.Errorf("failed to find results: %w", err)
				}

				var buf bytes.Buffer
				jp.EnableJSONOutput(true)
				for _, resultGroup := range results {
					if err := jp.PrintResults(&buf, resultGroup); err != nil {
						return stdout, stderr, fmt.Errorf("failed to print results: %w", err)
					}
				}

				if len(outFile) == 0 {
					stdout = buf.String()
				} else {
					err = os.WriteFile(s.Path(outFile), buf.Bytes(), 0644)
					if err != nil {
						return stdout, stderr, fmt.Errorf("could not write %q: %w", s.Path(outFile), err)
					}
				}
				return stdout, stderr, nil
			}, nil
		},
	)
}
