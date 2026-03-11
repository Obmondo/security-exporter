package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
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

		transport.TLSClientConfig = tlsConfig
	}

	timeout := 30 * time.Second
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

func (s *Scanner) Scan(ctx context.Context, c collector.Collector) (*ScanResult, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("getting hostname: %w", err)
	}

	pkgs, err := c.Packages(ctx)
	if err != nil {
		return nil, fmt.Errorf("collecting packages: %w", err)
	}

	req := ScanRequest{
		Family:     c.OSFamily(),
		Release:    c.Release(),
		ServerName: hostname,
		Packages:   pkgs,
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

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sending scan request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scan request failed with status %d", resp.StatusCode)
	}

	var result ScanResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding scan result: %w", err)
	}

	return &result, nil
}
