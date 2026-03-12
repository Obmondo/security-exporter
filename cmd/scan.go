package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"security-exporter/config"
	"security-exporter/internal/collector"
	"security-exporter/internal/scanner"
)

const defaultServerTimeout = 30 * time.Second

func scanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a single scan and print results to stdout",
		Long: `Run a one-shot vulnerability scan against the Vuls server.

Collects installed packages, sends them for scanning, and prints the
results to stdout. Useful for local testing and debugging.

The --server flag allows running a scan without a config file:
  obmondo-security-exporter scan --server http://localhost:5515`,
		RunE: runScan,
	}

	cmd.Flags().Bool("json", false, "output results as JSON")
	cmd.Flags().String("server", "", "Vuls server URL (skips config file when set)")
	cmd.Flags().Duration("timeout", defaultServerTimeout, "Vuls server request timeout")
	cmd.Flags().String("cert-file", "", "TLS client certificate file")
	cmd.Flags().String("key-file", "", "TLS client key file")
	cmd.Flags().String("ca-file", "", "TLS CA certificate file")

	return cmd
}

func runScan(cmd *cobra.Command, _ []string) error {
	const scanTimeout = 5 * time.Minute

	vulsServer, err := vulsServerFromFlags(cmd)
	if err != nil {
		return err
	}

	coll, err := collector.New()
	if err != nil {
		return err
	}

	sc, err := scanner.New(vulsServer)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	slog.Info("starting vulnerability scan")
	result, err := sc.Scan(ctx, coll)
	if err != nil {
		return err
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")
	if jsonOutput {
		return printJSON(result)
	}

	return printTable(result)
}

// vulsServerFromFlags returns a VulsServer built from --server flags if set,
// otherwise falls back to loading the config file.
func vulsServerFromFlags(cmd *cobra.Command) (config.VulsServer, error) {
	server, _ := cmd.Flags().GetString("server")
	if server != "" {
		timeout, _ := cmd.Flags().GetDuration("timeout")
		certFile, _ := cmd.Flags().GetString("cert-file")
		keyFile, _ := cmd.Flags().GetString("key-file")
		caFile, _ := cmd.Flags().GetString("ca-file")
		return config.VulsServer{
			URL:      server,
			Timeout:  config.Duration{Duration: timeout},
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   caFile,
		}, nil
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return config.VulsServer{}, err
	}
	return cfg.VulsServer, nil
}

func printJSON(result *scanner.ScanResult) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func printTable(result *scanner.ScanResult) error {
	const tabPadding = 2
	out := os.Stdout

	if _, err := fmt.Fprintf(out, "Host:    %s\nOS:      %s %s\nCVEs:    %d\nPackages with updates: %d / %d\n\n",
		result.ServerName, result.Family, result.Release,
		len(result.ScannedCves), countUpdates(result), len(result.Packages)); err != nil {
		return err
	}

	if len(result.ScannedCves) == 0 {
		_, err := fmt.Fprintln(out, "No vulnerabilities found.")
		return err
	}

	w := tabwriter.NewWriter(out, 0, 0, tabPadding, ' ', 0)
	if _, err := fmt.Fprintln(w, "CVE ID\tSCORE\tPACKAGE\tFIXED"); err != nil {
		return err
	}

	vulns := sortedVulns(result)
	for _, v := range vulns {
		score := bestScore(v)
		for _, pkg := range v.AffectedPackages {
			fixed := "yes"
			if pkg.NotFixedYet {
				fixed = "no"
			}
			if _, err := fmt.Fprintf(w, "%s\t%.1f\t%s\t%s\n", v.CveID, score, pkg.Name, fixed); err != nil {
				return err
			}
		}
	}

	return w.Flush()
}

func countUpdates(result *scanner.ScanResult) int {
	count := 0
	for _, pkg := range result.Packages {
		if pkg.NewVersion != "" {
			count++
		}
	}
	return count
}

func sortedVulns(result *scanner.ScanResult) []scanner.VulnInfo {
	vulns := make([]scanner.VulnInfo, 0, len(result.ScannedCves))
	for _, v := range result.ScannedCves {
		vulns = append(vulns, v)
	}
	sort.Slice(vulns, func(i, j int) bool {
		return bestScore(vulns[i]) > bestScore(vulns[j])
	})
	return vulns
}

func bestScore(v scanner.VulnInfo) float64 {
	var best float64
	for _, contents := range v.CveContents {
		for _, c := range contents {
			if c.Cvss3Score > best {
				best = c.Cvss3Score
			}
		}
	}
	return best
}
