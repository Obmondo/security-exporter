package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"security-exporter/config"
)

func TestScan_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	sc, err := New(config.VulsServer{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}

	coll := &mockCollector{family: "debian", release: "12", pkgs: "test\t1.0\n"}
	_, err = sc.Scan(context.Background(), coll)
	if err == nil {
		t.Fatal("expected error for server 500 response")
	}
}

func TestScan_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	sc, err := New(config.VulsServer{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}

	coll := &mockCollector{family: "debian", release: "12", pkgs: "test\t1.0\n"}
	_, err = sc.Scan(context.Background(), coll)
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
}

func TestScan_EmptyCves(t *testing.T) {
	mockResult := ScanResult{
		ServerName:  "test-host",
		Family:      "debian",
		Release:     "12",
		ScannedCves: map[string]VulnInfo{},
		Packages:    map[string]PackageInfo{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResult)
	}))
	defer server.Close()

	sc, err := New(config.VulsServer{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}

	coll := &mockCollector{family: "debian", release: "12", pkgs: "bash\t5.2\n"}
	result, err := sc.Scan(context.Background(), coll)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ScannedCves) != 0 {
		t.Errorf("expected 0 CVEs, got %d", len(result.ScannedCves))
	}
}

func TestScan_MultiplePackagesAndCves(t *testing.T) {
	mockResult := ScanResult{
		ServerName: "prod-server",
		Family:     "redhat",
		Release:    "9",
		ScannedCves: map[string]VulnInfo{
			"CVE-2024-0001": {
				CveID: "CVE-2024-0001",
				CveContents: map[string][]CveContent{
					"nvd": {{CveID: "CVE-2024-0001", Cvss3Score: 9.8}},
				},
				AffectedPackages: []AffectedPackage{
					{Name: "openssl", NotFixedYet: false},
				},
			},
			"CVE-2024-0002": {
				CveID: "CVE-2024-0002",
				CveContents: map[string][]CveContent{
					"nvd": {{CveID: "CVE-2024-0002", Cvss3Score: 4.3}},
				},
				AffectedPackages: []AffectedPackage{
					{Name: "kernel", NotFixedYet: true},
				},
			},
		},
		Packages: map[string]PackageInfo{
			"openssl": {Name: "openssl", Version: "3.0.7-1", NewVersion: "3.0.8-1"},
			"kernel":  {Name: "kernel", Version: "5.14.0-1", NewVersion: ""},
			"bash":    {Name: "bash", Version: "5.2.15-1", NewVersion: ""},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResult)
	}))
	defer server.Close()

	sc, err := New(config.VulsServer{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}

	coll := &mockCollector{
		family:  "redhat",
		release: "9",
		pkgs:    "openssl\t0:3.0.7-1.el9\nkernel\t0:5.14.0-1.el9\nbash\t0:5.2.15-1.el9\n",
	}

	result, err := sc.Scan(context.Background(), coll)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.ScannedCves) != 2 {
		t.Errorf("expected 2 CVEs, got %d", len(result.ScannedCves))
	}

	cve1, ok := result.ScannedCves["CVE-2024-0001"]
	if !ok {
		t.Fatal("expected CVE-2024-0001 in results")
	}
	if cve1.AffectedPackages[0].Name != "openssl" {
		t.Errorf("expected openssl affected, got %s", cve1.AffectedPackages[0].Name)
	}

	cve2, ok := result.ScannedCves["CVE-2024-0002"]
	if !ok {
		t.Fatal("expected CVE-2024-0002 in results")
	}
	if !cve2.AffectedPackages[0].NotFixedYet {
		t.Error("expected kernel CVE to be marked as not fixed yet")
	}

	if len(result.Packages) != 3 {
		t.Errorf("expected 3 packages, got %d", len(result.Packages))
	}
}

func TestScan_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow server — but context should cancel before response
		<-r.Context().Done()
	}))
	defer server.Close()

	sc, err := New(config.VulsServer{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	coll := &mockCollector{family: "debian", release: "12", pkgs: "test\t1.0\n"}
	_, err = sc.Scan(ctx, coll)
	if err == nil {
		t.Fatal("expected error for cancelled context")
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
