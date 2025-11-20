//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"log"
	"os"

	"go.yaml.in/yaml/v3"
	"golang.org/x/mod/modfile"
)

type Config struct {
	Replaces []Replace `yaml:"replaces"`
}

type Replace struct {
	OldPath    string `yaml:"oldPath"`
	OldVersion string `yaml:"oldVersion"`
	NewPath    string `yaml:"newPath"`
	NewVersion string `yaml:"newVersion"`
}

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("usage: %s <go.mod path> <config file path>", os.Args[0])
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatalf("failed to read go.mod: %v", err)
	}

	gomod, err := modfile.Parse(os.Args[1], data, nil)
	if err != nil {
		log.Fatalf("failed to parse go.mod: %v", err)
	}

	data, err = os.ReadFile(os.Args[2])
	if err != nil {
		log.Fatalf("failed to read config file: %v", err)
	}

	var config Config
	if err = yaml.Unmarshal(data, &config); err != nil {
		log.Fatalf("failed to unmarshal config file: %v", err)
	}

	// Apply replacements from config. When there's an existing replace
	// directive and the module path and version match, it will be
	// replaced. Otherwise, a new replace directive will be added.
	for _, replace := range config.Replaces {
		if err = gomod.AddReplace(replace.OldPath, replace.OldVersion, replace.NewPath, replace.NewVersion); err != nil {
			log.Fatalf("failed to add replace for module %q version %q: %v", replace.OldPath, replace.OldVersion, err)
		}
	}

	newData, err := gomod.Format()
	if err != nil {
		log.Fatalf("failed to format modified go.mod: %v", err)
	}

	if err := os.WriteFile(os.Args[1], newData, 0644); err != nil {
		log.Fatalf("failed to write modified go.mod: %v", err)
	}
}
