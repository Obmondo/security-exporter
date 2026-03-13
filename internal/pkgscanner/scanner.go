package pkgscanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"security-exporter/config"
	"security-exporter/internal/collector"
)

type Scanner struct {
	client    *http.Client
	serverURL string
}

func New(cfg config.VulsServer) (*Scanner, error) {
	transport := &http.Transport{}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		slog.Info("configuring mTLS", "cert", cfg.CertFile, "ca", cfg.CAFile)

		tlsConfig, err := buildTLSConfig(cfg)
		if err != nil {
			return nil, err
		}

		transport.TLSClientConfig = tlsConfig
	}

	const defaultTimeout = 5 * time.Minute
	timeout := defaultTimeout
	if cfg.Timeout.Duration > 0 {
		timeout = cfg.Timeout.Duration
	}

	return &Scanner{
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
		serverURL: cfg.URL,
	}, nil
}

func buildTLSConfig(cfg config.VulsServer) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading client certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA certificate: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caPool
	}

	return tlsConfig, nil
}

func (s *Scanner) Scan(ctx context.Context, c collector.Collector) (*ScanResult, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("getting hostname: %w", err)
	}

	pkgsRaw, srcRaw, err := c.CollectPackages(ctx)
	if err != nil {
		return nil, fmt.Errorf("collecting packages: %w", err)
	}

	packages := ParsePackages(pkgsRaw)

	updates, err := c.AvailableUpdates(ctx)
	if err != nil {
		slog.Warn("failed to collect available updates", "error", err)
	}
	for name, newVer := range updates {
		if pkg, ok := packages[name]; ok {
			pkg.NewVersion = newVer
			packages[name] = pkg
		}
	}

	req := ScanRequest{
		Family:     c.OSFamily(),
		Release:    c.Release(),
		ServerName: hostname,
		Packages:   packages,
	}

	if srcRaw != "" {
		req.SrcPackages = filterSrcPackages(ParseSrcPackages(srcRaw), packages)
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.serverURL+"/vuls", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	slog.Info("sending scan request", "url", s.serverURL+"/vuls", "package_count", len(req.Packages))

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sending scan request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		slog.Error("scan request rejected", "status", resp.StatusCode, "body", string(respBody))
		return nil, fmt.Errorf("scan request failed with status %d", resp.StatusCode)
	}

	slog.Info("scan completed successfully", "status", resp.StatusCode)

	var results []ScanResult
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, fmt.Errorf("decoding scan result: %w", err)
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("vuls server returned empty results array")
	}

	// Merge back locally-collected newVersion into server response.
	// The server returns its own Packages map where newVersion is always empty.
	for name, reqPkg := range packages {
		if reqPkg.NewVersion != "" {
			if resPkg, ok := results[0].Packages[name]; ok {
				resPkg.NewVersion = reqPkg.NewVersion
				results[0].Packages[name] = resPkg
			}
		}
	}

	return &results[0], nil
}

// filterSrcPackages removes binary names that don't exist in packages and
// drops source packages with no remaining binaries. The vuls2 server looks
// up each binary name in the Packages map and errors if not found.
func filterSrcPackages(srcPkgs SrcPackages, packages Packages) SrcPackages {
	for srcName, sp := range srcPkgs {
		var filtered []string
		for _, bn := range sp.BinaryNames {
			if _, ok := packages[bn]; ok {
				filtered = append(filtered, bn)
			}
		}
		if len(filtered) == 0 {
			delete(srcPkgs, srcName)
		} else {
			sp.BinaryNames = filtered
			srcPkgs[srcName] = sp
		}
	}
	return srcPkgs
}
