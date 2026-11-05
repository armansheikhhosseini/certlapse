// Package cli wires the command-line interface.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// ExitError ends the program with Code without printing anything more.
type ExitError struct{ Code int }

func (e ExitError) Error() string { return fmt.Sprintf("exit code %d", e.Code) }

// NewRootCommand builds the certlapse command tree.
func NewRootCommand(version string) *cobra.Command {
	root := &cobra.Command{
		Use:           "certlapse",
		Short:         "Find every TLS certificate and whether it renews itself",
		Long:          "certlapse finds TLS certificates and reports which ones renew automatically, which are renewed by hand, and which will break as public certificate lifetimes shrink to 100 days (15 Mar 2027) and 47 days (15 Mar 2029).",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newScanCommand(), newVersionCommand(version))
	return root
}

func newVersionCommand(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version)
		},
	}
}
