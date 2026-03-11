package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"security-exporter/internal/scanner"
)

func TestUpdate(t *testing.T) {
	result := &scanner.ScanResult{
		Packages: map[string]scanner.PackageInfo{
			"openssl":        {Name: "openssl", Version: "3.0.13-1", NewVersion: "3.0.14-1"},
			"bash":           {Name: "bash", Version: "5.2.21-1", NewVersion: ""},
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
