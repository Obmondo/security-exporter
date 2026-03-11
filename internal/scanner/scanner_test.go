package scanner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"security-exporter/config"
)

type mockCollector struct {
	family  string
	release string
	pkgs    string
}

func (m *mockCollector) Packages(_ context.Context) (string, error) { return m.pkgs, nil }
func (m *mockCollector) OSFamily() string                           { return m.family }
func (m *mockCollector) Release() string                            { return m.release }

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
		if req.Packages != "openssl\t3.0.13-1\n" {
			t.Errorf("unexpected packages: %s", req.Packages)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResult)
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
