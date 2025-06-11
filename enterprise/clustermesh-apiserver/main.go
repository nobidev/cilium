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
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/clustermesh-apiserver/clustermesh"
	"github.com/cilium/cilium/clustermesh-apiserver/cmd"
	"github.com/cilium/cilium/clustermesh-apiserver/kvstoremesh"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	cment "github.com/cilium/cilium/enterprise/clustermesh-apiserver/clustermesh"
	kment "github.com/cilium/cilium/enterprise/clustermesh-apiserver/kvstoremesh"
)

func main() {
	replace := func(ent *cobra.Command) {
		oss, _, err := cmd.RootCmd.Find([]string{ent.Name()})
		if err != nil {
			// slogloggercheck: logger not yet initialized
			logging.Fatal(logging.DefaultSlogLogger, "Could not find OSS command", logfields.Cmd, ent.Name())
		}
		cmd.RootCmd.RemoveCommand(oss)
		cmd.RootCmd.AddCommand(ent)
	}

	// Replace the OSS commands with the corresponding enterprise ones.
	replace(clustermesh.NewCmd(hive.New(cment.EnterpriseClusterMesh)))
	replace(kvstoremesh.NewCmd(hive.New(kment.EnterpriseKVStoreMesh)))

	cmd.Execute()
}
