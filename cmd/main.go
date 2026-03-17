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

const binaryName = "obmondo-security-exporter"

func main() {
	root := &cobra.Command{
		Use:     "obmondo-security-exporter",
		Short:   "Prometheus exporter for vulnerability scanning via Vuls",
		Version: Version,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			level := slog.LevelWarn
			if debug, _ := cmd.Flags().GetBool("debug"); debug {
				level = slog.LevelInfo
			}
			slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
			slog.Info("starting exporter", "binary", binaryName, "version", Version)
		},
	}

	root.PersistentFlags().StringVarP(&configPath, "config", "c", "/etc/obmondo/security-exporter/config.yaml", "path to config file")

	root.AddCommand(serveCmd(), scanCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
