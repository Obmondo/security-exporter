package scanner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"security-exporter/config"
)

type mockCollector struct {
	family  string
	release string
	pkgs    string
	err     error
}

func (m *mockCollector) Packages(_ context.Context) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.pkgs, nil
}
func (m *mockCollector) OSFamily() string { return m.family }
func (m *mockCollector) Release() string  { return m.release }

func TestScan(t *testing.T) {
	mockResult := ScanResult{
		ServerName: "test-host",
		Family:     "debian",
		Release:    "12",
		ScannedCves: map[string]VulnInfo{
			"CVE-2024-1234": {
				CveID: "CVE-2024-1234",
				AffectedPackages: []AffectedPackage{
					{Name: "openssl", NotFixedYet: false},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/vuls" {
			t.Errorf("expected path /vuls, got %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		body, _ := io.ReadAll(r.Body)
		var req ScanRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("failed to unmarshal request: %v", err)
		}
		if req.Family != "debian" {
			t.Errorf("expected family debian, got %s", req.Family)
		}
		if len(req.Packages) != 1 {
			t.Errorf("expected 1 package, got %d", len(req.Packages))
		}
		if pkg, ok := req.Packages["openssl"]; !ok || pkg.Version != "3.0.13-1" {
			t.Errorf("unexpected packages: %v", req.Packages)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]ScanResult{mockResult})
	}))
	defer server.Close()

	sc, err := New(config.VulsServer{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}

	coll := &mockCollector{
		family:  "debian",
		release: "12",
		pkgs:    "openssl\t3.0.13-1\n",
	}

	result, err := sc.Scan(context.Background(), coll)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.ScannedCves) != 1 {
		t.Errorf("expected 1 CVE, got %d", len(result.ScannedCves))
	}
	if _, ok := result.ScannedCves["CVE-2024-1234"]; !ok {
		t.Error("expected CVE-2024-1234 in results")
	}
}

func TestScan_ContentTypeHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]ScanResult{{}})
	}))
	defer server.Close()

	sc, err := New(config.VulsServer{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}

	coll := &mockCollector{family: "debian", release: "12", pkgs: "test\t1.0\n"}
	_, err = sc.Scan(context.Background(), coll)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScan_RequestBody(t *testing.T) {
	var received ScanRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &received)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]ScanResult{{}})
	}))
	defer server.Close()

	sc, err := New(config.VulsServer{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}

	coll := &mockCollector{family: "redhat", release: "9", pkgs: "bash\t5.2\n"}
	_, err = sc.Scan(context.Background(), coll)
	if err != nil {
		t.Fatal(err)
	}

	if received.Family != "redhat" {
		t.Errorf("expected family redhat, got %s", received.Family)
	}
	if received.Release != "9" {
		t.Errorf("expected release 9, got %s", received.Release)
	}
	if len(received.Packages) != 1 {
		t.Errorf("expected 1 package, got %d", len(received.Packages))
	}
	if pkg, ok := received.Packages["bash"]; !ok || pkg.Version != "5.2" {
		t.Errorf("unexpected packages: %v", received.Packages)
	}
	if received.ServerName == "" {
		t.Error("expected non-empty ServerName (hostname)")
	}
}

func TestScan_CollectorError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("server should not be called when collector fails")
	}))
	defer server.Close()

	sc, err := New(config.VulsServer{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}

	coll := &mockCollector{
		family: "debian",
		err:    io.ErrUnexpectedEOF,
	}
	_, err = sc.Scan(context.Background(), coll)
	if err == nil {
		t.Fatal("expected error when collector fails")
	}
}

func TestNew_NoTLS(t *testing.T) {
	sc, err := New(config.VulsServer{URL: "http://localhost:5515"})
	if err != nil {
		t.Fatal(err)
	}
	if sc.serverURL != "http://localhost:5515" {
		t.Errorf("expected URL http://localhost:5515, got %s", sc.serverURL)
	}
}

func TestNew_CustomTimeout(t *testing.T) {
	sc, err := New(config.VulsServer{
		URL:     "http://localhost:5515",
		Timeout: config.Duration{Duration: 2 * time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sc.client.Timeout != 2*time.Minute {
		t.Errorf("expected timeout 2m, got %s", sc.client.Timeout)
	}
}

func TestNew_DefaultTimeout(t *testing.T) {
	sc, err := New(config.VulsServer{URL: "http://localhost:5515"})
	if err != nil {
		t.Fatal(err)
	}
	const defaultTimeout = 5 * time.Minute
	if sc.client.Timeout != defaultTimeout {
		t.Errorf("expected default timeout %s, got %s", defaultTimeout, sc.client.Timeout)
	}
}

func TestNew_InvalidCertFile(t *testing.T) {
	_, err := New(config.VulsServer{
		URL:      "https://localhost:5515",
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	})
	if err == nil {
		t.Fatal("expected error for invalid cert file")
	}
}

func TestBuildTLSConfig_InvalidCertFile(t *testing.T) {
	_, err := buildTLSConfig(config.VulsServer{
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	})
	if err == nil {
		t.Fatal("expected error for invalid cert file")
	}
}

func TestBuildTLSConfig_InvalidCAFile(t *testing.T) {
	// Create a minimal self-signed cert+key for the test
	certPEM, keyPEM := generateTestCert(t)

	certFile := writeTempFile(t, certPEM)
	keyFile := writeTempFile(t, keyPEM)

	_, err := buildTLSConfig(config.VulsServer{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   "/nonexistent/ca.pem",
	})
	if err == nil {
		t.Fatal("expected error for invalid CA file")
	}
}

func TestBuildTLSConfig_InvalidCAPEM(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)

	certFile := writeTempFile(t, certPEM)
	keyFile := writeTempFile(t, keyPEM)
	caFile := writeTempFile(t, "not a PEM certificate")

	_, err := buildTLSConfig(config.VulsServer{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	})
	if err == nil {
		t.Fatal("expected error for invalid CA PEM content")
	}
}

func TestBuildTLSConfig_ValidCertNoCA(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)

	certFile := writeTempFile(t, certPEM)
	keyFile := writeTempFile(t, keyPEM)

	tlsCfg, err := buildTLSConfig(config.VulsServer{
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(tlsCfg.Certificates))
	}
	if tlsCfg.RootCAs != nil {
		t.Error("expected nil RootCAs when no CA file specified")
	}
}

func TestBuildTLSConfig_ValidCertWithCA(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)

	certFile := writeTempFile(t, certPEM)
	keyFile := writeTempFile(t, keyPEM)
	caFile := writeTempFile(t, certPEM) // reuse cert as CA for test

	tlsCfg, err := buildTLSConfig(config.VulsServer{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(tlsCfg.Certificates))
	}
	if tlsCfg.RootCAs == nil {
		t.Error("expected non-nil RootCAs when CA file specified")
	}
}
