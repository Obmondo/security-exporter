package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Version is set at build time via ldflags.
	Version    = "dev"
	configPath string
)

func main() {
	root := &cobra.Command{
		Use:     "obmondo-security-exporter",
		Short:   "Prometheus exporter for vulnerability scanning via Vuls",
		Version: Version,
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
		},
	}

	root.PersistentFlags().StringVarP(&configPath, "config", "c", "/etc/obmondo/security-exporter/config.yaml", "path to config file")

	root.AddCommand(serveCmd(), scanCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
