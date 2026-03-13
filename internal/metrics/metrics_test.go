package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"security-exporter/internal/scanner"
)

func TestUpdate(t *testing.T) {
	result := &scanner.ScanResult{
		Packages: scanner.Packages{
			"openssl":         {Name: "openssl", Version: "3.0.13-1", NewVersion: "3.0.14-1"},
			"bash":            {Name: "bash", Version: "5.2.21-1", NewVersion: ""},
			"linux-image-6.1": {Name: "linux-image-6.1", Version: "6.1.90-1", NewVersion: "6.1.99-1"},
		},
		ScannedCves: map[string]scanner.VulnInfo{
			"CVE-2024-1234": {
				CveID: "CVE-2024-1234",
				CveContents: map[string][]scanner.CveContent{
					"nvd": {{CveID: "CVE-2024-1234", Cvss3Score: 7.5}},
				},
				AffectedPackages: []scanner.AffectedPackage{
					{Name: "openssl"},
				},
			},
			"CVE-2024-5678": {
				CveID: "CVE-2024-5678",
				CveContents: map[string][]scanner.CveContent{
					"nvd": {{CveID: "CVE-2024-5678", Cvss3Score: 5.0}},
				},
				AffectedPackages: []scanner.AffectedPackage{
					{Name: "linux-image-6.1"},
				},
			},
		},
	}

	Update(result)

	if v := testutil.ToFloat64(totalPackagesWithUpdate); v != 2 {
		t.Errorf("expected 2 packages with updates, got %f", v)
	}
	if v := testutil.ToFloat64(kernelUpdateAvailable); v != 1 {
		t.Errorf("expected kernel update available = 1, got %f", v)
	}
}

func TestUpdate_GeneralCVEGauge(t *testing.T) {
	result := &scanner.ScanResult{
		Packages: scanner.Packages{
			"openssl": {Name: "openssl", Version: "3.0.13-1", NewVersion: "3.0.14-1"},
		},
		ScannedCves: map[string]scanner.VulnInfo{
			"CVE-2024-1234": {
				CveID: "CVE-2024-1234",
				CveContents: map[string][]scanner.CveContent{
					"nvd": {{CveID: "CVE-2024-1234", Cvss3Score: 7.5}},
				},
				AffectedPackages: []scanner.AffectedPackage{
					{Name: "openssl"},
				},
			},
		},
	}

	Update(result)

	v := testutil.ToFloat64(generalCVEDetails.WithLabelValues("openssl", "CVE-2024-1234", "7.5"))
	if v != 7.5 {
		t.Errorf("expected general CVE gauge 7.5, got %f", v)
	}
}

func TestUpdate_KernelCVEGauge(t *testing.T) {
	result := &scanner.ScanResult{
		Packages: scanner.Packages{
			"linux-image-6.1": {Name: "linux-image-6.1", Version: "6.1.90-1", NewVersion: "6.1.99-1"},
		},
		ScannedCves: map[string]scanner.VulnInfo{
			"CVE-2024-5678": {
				CveID: "CVE-2024-5678",
				CveContents: map[string][]scanner.CveContent{
					"nvd": {{CveID: "CVE-2024-5678", Cvss3Score: 5.0}},
				},
				AffectedPackages: []scanner.AffectedPackage{
					{Name: "linux-image-6.1"},
				},
			},
		},
	}

	Update(result)

	v := testutil.ToFloat64(kernelCVEDetails.WithLabelValues("linux-image-6.1", "CVE-2024-5678", "5.0"))
	if v != 5.0 {
		t.Errorf("expected kernel CVE gauge 5.0, got %f", v)
	}
}

func TestUpdate_ResetsBetweenCalls(t *testing.T) {
	first := &scanner.ScanResult{
		Packages: scanner.Packages{
			"openssl": {Name: "openssl", Version: "3.0.13-1", NewVersion: "3.0.14-1"},
		},
		ScannedCves: map[string]scanner.VulnInfo{
			"CVE-2024-1234": {
				CveID: "CVE-2024-1234",
				CveContents: map[string][]scanner.CveContent{
					"nvd": {{CveID: "CVE-2024-1234", Cvss3Score: 7.5}},
				},
				AffectedPackages: []scanner.AffectedPackage{
					{Name: "openssl"},
				},
			},
		},
	}
	Update(first)

	second := &scanner.ScanResult{
		Packages:    scanner.Packages{},
		ScannedCves: map[string]scanner.VulnInfo{},
	}
	Update(second)

	if v := testutil.ToFloat64(totalPackagesWithUpdate); v != 0 {
		t.Errorf("expected 0 after second update, got %f", v)
	}
}
