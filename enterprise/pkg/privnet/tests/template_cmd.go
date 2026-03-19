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
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/cilium/hive/script"
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
