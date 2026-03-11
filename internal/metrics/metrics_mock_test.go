package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"security-exporter/internal/scanner"
)

func TestUpdate_NoCves(t *testing.T) {
	result := &scanner.ScanResult{
		Packages: map[string]scanner.PackageInfo{
			"bash": {Name: "bash", Version: "5.2.21-1", NewVersion: ""},
		},
		ScannedCves: map[string]scanner.VulnInfo{},
	}

	Update(result)

	if v := testutil.ToFloat64(totalPackagesWithUpdate); v != 0 {
		t.Errorf("expected 0 packages with updates, got %f", v)
	}
	if v := testutil.ToFloat64(kernelUpdateAvailable); v != 0 {
		t.Errorf("expected kernel update available = 0, got %f", v)
	}
}

func TestUpdate_KernelOnly(t *testing.T) {
	result := &scanner.ScanResult{
		Packages: map[string]scanner.PackageInfo{
			"linux-image-6.1": {Name: "linux-image-6.1", Version: "6.1.90-1", NewVersion: "6.1.99-1"},
		},
		ScannedCves: map[string]scanner.VulnInfo{
			"CVE-2024-9999": {
				CveID: "CVE-2024-9999",
				CveContents: map[string][]scanner.CveContent{
					"nvd": {{CveID: "CVE-2024-9999", Cvss3Score: 8.1}},
				},
				AffectedPackages: []scanner.AffectedPackage{
					{Name: "linux-image-6.1"},
				},
			},
		},
	}

	Update(result)

	if v := testutil.ToFloat64(totalPackagesWithUpdate); v != 1 {
		t.Errorf("expected 1 package with update, got %f", v)
	}
	if v := testutil.ToFloat64(kernelUpdateAvailable); v != 1 {
		t.Errorf("expected kernel update available = 1, got %f", v)
	}
}

func TestUpdate_MultipleCveSources(t *testing.T) {
	result := &scanner.ScanResult{
		Packages: map[string]scanner.PackageInfo{
			"openssl": {Name: "openssl", Version: "3.0.13-1", NewVersion: "3.0.14-1"},
		},
		ScannedCves: map[string]scanner.VulnInfo{
			"CVE-2024-1111": {
				CveID: "CVE-2024-1111",
				CveContents: map[string][]scanner.CveContent{
					"nvd":   {{CveID: "CVE-2024-1111", Cvss3Score: 6.5}},
					"mitre": {{CveID: "CVE-2024-1111", Cvss3Score: 7.2}},
				},
				AffectedPackages: []scanner.AffectedPackage{
					{Name: "openssl"},
				},
			},
		},
	}

	Update(result)

	// Should use best score (7.2 from mitre)
	if v := testutil.ToFloat64(totalPackagesWithUpdate); v != 1 {
		t.Errorf("expected 1 package with update, got %f", v)
	}
}

func TestUpdate_RPMKernelPackage(t *testing.T) {
	result := &scanner.ScanResult{
		Packages: map[string]scanner.PackageInfo{
			"kernel-core": {Name: "kernel-core", Version: "5.14.0-1", NewVersion: "5.14.0-2"},
		},
		ScannedCves: map[string]scanner.VulnInfo{
			"CVE-2024-7777": {
				CveID: "CVE-2024-7777",
				CveContents: map[string][]scanner.CveContent{
					"nvd": {{CveID: "CVE-2024-7777", Cvss3Score: 5.5}},
				},
				AffectedPackages: []scanner.AffectedPackage{
					{Name: "kernel-core"},
				},
			},
		},
	}

	Update(result)

	if v := testutil.ToFloat64(kernelUpdateAvailable); v != 1 {
		t.Errorf("expected kernel update available = 1, got %f", v)
	}
}

func TestUpdate_EmptyResult(t *testing.T) {
	result := &scanner.ScanResult{
		Packages:    map[string]scanner.PackageInfo{},
		ScannedCves: map[string]scanner.VulnInfo{},
	}

	Update(result)

	if v := testutil.ToFloat64(totalPackagesWithUpdate); v != 0 {
		t.Errorf("expected 0 packages with updates, got %f", v)
	}
	if v := testutil.ToFloat64(kernelUpdateAvailable); v != 0 {
		t.Errorf("expected kernel update available = 0, got %f", v)
	}
}
