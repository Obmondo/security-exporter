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

const defaultServerTimeout = 5 * time.Minute

func scanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a single scan and print results to stdout",
		Long: `Run a one-shot vulnerability scan and print results to stdout.

Without --server, runs in local-only mode: collects installed packages
and displays them without contacting a Vuls server.

With --server, sends packages to the Vuls server for CVE scanning
(requires --cert-file and --key-file for mTLS):
  obmondo-security-exporter scan --server https://vuls.obmondo.com --cert-file tls.crt --key-file tls.key`,
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

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	var result *scanner.ScanResult

	if vulsServer.URL == "" {
		slog.Info("running in local-only mode (no server URL configured)")
		result, err = localScan(ctx, coll)
		if err != nil {
			return err
		}

		return printResult(cmd, result)
	}

	sc, err := scanner.New(vulsServer)
	if err != nil {
		return err
	}

	slog.Info("starting vulnerability scan")
	result, err = sc.Scan(ctx, coll)
	if err != nil {
		return err
	}

	slog.Info("scan complete",
		"server", vulsServer.URL,
		"cves", len(result.ScannedCves),
		"packages", len(result.Packages),
		"updates", countUpdates(result),
	)

	return nil
}

func printResult(cmd *cobra.Command, result *scanner.ScanResult) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")
	if jsonOutput {
		return printJSON(result)
	}
	return printTable(result)
}

// localScan collects packages and builds a ScanResult without contacting a server.
func localScan(ctx context.Context, coll collector.Collector) (*scanner.ScanResult, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("getting hostname: %w", err)
	}

	pkgs, err := coll.Packages(ctx)
	if err != nil {
		return nil, fmt.Errorf("collecting packages: %w", err)
	}

	packages := scanner.ParsePackages(pkgs)

	updates, err := coll.AvailableUpdates(ctx)
	if err != nil {
		slog.Warn("failed to collect available updates", "error", err)
	}
	for name, newVer := range updates {
		if pkg, ok := packages[name]; ok {
			pkg.NewVersion = newVer
			packages[name] = pkg
		}
	}

	result := &scanner.ScanResult{
		ServerName:  hostname,
		Family:      coll.OSFamily(),
		Release:     coll.Release(),
		Packages:    packages,
		ScannedCves: map[string]scanner.VulnInfo{},
	}

	srcRaw, err := coll.SrcPackages(ctx)
	if err != nil {
		slog.Warn("failed to collect source packages", "error", err)
	}
	if srcRaw != "" {
		result.SrcPackages = scanner.ParseSrcPackages(srcRaw)
	}

	return result, nil
}

// vulsServerFromFlags builds a VulsServer from flags/env vars. When --server
// is not set and no config file is available, returns an empty VulsServer
// (triggering local-only mode).
func vulsServerFromFlags(cmd *cobra.Command) (config.VulsServer, error) {
	server, _ := cmd.Flags().GetString("server")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	certFile := flagOrEnv(cmd, "cert-file", "VULS_CERT_FILE")
	keyFile := flagOrEnv(cmd, "key-file", "VULS_KEY_FILE")
	caFile := flagOrEnv(cmd, "ca-file", "VULS_CA_FILE")

	// If --server is explicitly provided, use flag-based config.
	if server != "" {
		if certFile == "" || keyFile == "" {
			return config.VulsServer{}, fmt.Errorf(
				"TLS certificates are required to connect to the vuls server. " +
					"Provide --cert-file and --key-file (or VULS_CERT_FILE / VULS_KEY_FILE)")
		}
		return config.VulsServer{
			URL:      server,
			Timeout:  config.Duration{Duration: timeout},
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   caFile,
		}, nil
	}

	// Try loading from config file; if it fails, fall back to local-only mode.
	if configPath != "" {
		cfg, err := config.Load(configPath)
		if err == nil && cfg.VulsServer.URL != "" {
			return cfg.VulsServer, nil
		}
	}

	// Warn if TLS certs are provided but no server URL.
	if certFile != "" || keyFile != "" {
		slog.Warn("TLS certificates provided but no server URL specified, running in local-only mode")
	}

	return config.VulsServer{}, nil
}

// flagOrEnv returns the flag value if non-empty, otherwise the environment variable.
func flagOrEnv(cmd *cobra.Command, flagName, envName string) string {
	val, _ := cmd.Flags().GetString(flagName)
	if val != "" {
		return val
	}
	return os.Getenv(envName)
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
		msg := "No vulnerabilities found."
		if countUpdates(result) == 0 && len(result.Packages) > 0 {
			msg = "No vulnerabilities scanned (local-only mode, no server contacted)."
		}
		_, err := fmt.Fprintln(out, msg)
		return err
	}

	w := tabwriter.NewWriter(out, 0, 0, tabPadding, ' ', 0)
	if _, err := fmt.Fprintln(w, "CVE ID\tSCORE\tPACKAGE\tFIXED\tFIX VERSION"); err != nil {
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
			fixVer := pkg.FixedIn
			if fixVer == "" {
				fixVer = "-"
			}
			if _, err := fmt.Fprintf(w, "%s\t%.1f\t%s\t%s\t%s\n", v.CveID, score, pkg.Name, fixed, fixVer); err != nil {
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
