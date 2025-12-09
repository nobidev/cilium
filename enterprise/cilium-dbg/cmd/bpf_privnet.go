package cmd

import (
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/cilium-dbg/cmd"
)

var BPFPrivNetCmd = &cobra.Command{
	Use:     "private-network",
	Aliases: []string{"privnet"},
	Short:   "Manage private network maps",
}

func init() {
	cmd.BPFCmd.AddCommand(BPFPrivNetCmd)
}
