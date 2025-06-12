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
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/cmdref"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

func main() {
	binaryName := filepath.Base(os.Args[0])

	cmd := &cobra.Command{
		Use:   binaryName,
		Short: "Run " + binaryName,
		RunE: func(cobraCmd *cobra.Command, args []string) error {
			logger := logging.DefaultSlogLogger.With(logfields.LogSubsys, binaryName)
			return Hive.Run(logger)
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			if Hive.Viper().GetBool("debug") {
				logging.SetSlogLevel(slog.LevelDebug)
			}
			option.Config.SetupLogging(Hive.Viper(), "external-dns-proxy")
			option.Config.Populate(log, Hive.Viper())
			option.LogRegisteredSlogOptions(Hive.Viper(), log)
		},
	}

	Hive.RegisterFlags(cmd.Flags())
	cmd.AddCommand(
		cmdref.NewCmd(cmd),
		Hive.Command(),
	)

	cmd.Execute()
}
