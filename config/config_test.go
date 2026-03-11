package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	content := `
vuls_server:
  url: "https://vuls.example.com"
  timeout: 45s
  cert_file: "/etc/ssl/cert.pem"
  key_file: "/etc/ssl/key.pem"
  ca_file: "/etc/ssl/ca.pem"
listen_address: "127.0.0.1:9090"
cron_expression: "0 */6 * * *"
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.VulsServer.URL != "https://vuls.example.com" {
		t.Errorf("expected URL https://vuls.example.com, got %s", cfg.VulsServer.URL)
	}
	if cfg.VulsServer.Timeout.Duration != 45*time.Second {
		t.Errorf("expected timeout 45s, got %s", cfg.VulsServer.Timeout.Duration)
	}
	if cfg.VulsServer.CertFile != "/etc/ssl/cert.pem" {
		t.Errorf("expected cert_file /etc/ssl/cert.pem, got %s", cfg.VulsServer.CertFile)
	}
	if cfg.VulsServer.KeyFile != "/etc/ssl/key.pem" {
		t.Errorf("expected key_file /etc/ssl/key.pem, got %s", cfg.VulsServer.KeyFile)
	}
	if cfg.VulsServer.CAFile != "/etc/ssl/ca.pem" {
		t.Errorf("expected ca_file /etc/ssl/ca.pem, got %s", cfg.VulsServer.CAFile)
	}
	if cfg.ListenAddress != "127.0.0.1:9090" {
		t.Errorf("expected listen_address 127.0.0.1:9090, got %s", cfg.ListenAddress)
	}
	if cfg.CronExpression != "0 */6 * * *" {
		t.Errorf("expected cron_expression '0 */6 * * *', got %s", cfg.CronExpression)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("{{invalid yaml"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoad_InvalidDuration(t *testing.T) {
	content := `
vuls_server:
  url: "https://example.com"
  timeout: "not-a-duration"
listen_address: "127.0.0.1:9090"
cron_expression: "* * * * *"
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid duration")
	}
}

func TestLoad_Defaults(t *testing.T) {
	content := `
vuls_server:
  url: "https://example.com"
listen_address: "127.0.0.1:9090"
cron_expression: "* * * * *"
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.VulsServer.Timeout.Duration != 0 {
		t.Errorf("expected zero timeout when not set, got %s", cfg.VulsServer.Timeout.Duration)
	}
	if cfg.VulsServer.CertFile != "" {
		t.Errorf("expected empty cert_file, got %s", cfg.VulsServer.CertFile)
	}
}
