package prommetrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"security-exporter/internal/pkgscanner"
)

func TestUpdate_NoCves(t *testing.T) {
	result := &pkgscanner.ScanResult{
		Packages: pkgscanner.Packages{
			"bash": {Name: "bash", Version: "5.2.21-1", NewVersion: ""},
		},
		ScannedCves: map[string]pkgscanner.VulnInfo{},
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
	result := &pkgscanner.ScanResult{
		Packages: pkgscanner.Packages{
			"linux-image-6.1": {Name: "linux-image-6.1", Version: "6.1.90-1", NewVersion: "6.1.99-1"},
		},
		ScannedCves: map[string]pkgscanner.VulnInfo{
			"CVE-2024-9999": {
				CveID: "CVE-2024-9999",
				CveContents: map[string][]pkgscanner.CveContent{
					"nvd": {{CveID: "CVE-2024-9999", Cvss3Score: 8.1}},
				},
				AffectedPackages: []pkgscanner.AffectedPackage{
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
	result := &pkgscanner.ScanResult{
		Packages: pkgscanner.Packages{
			"openssl": {Name: "openssl", Version: "3.0.13-1", NewVersion: "3.0.14-1"},
		},
		ScannedCves: map[string]pkgscanner.VulnInfo{
			"CVE-2024-1111": {
				CveID: "CVE-2024-1111",
				CveContents: map[string][]pkgscanner.CveContent{
					"nvd":   {{CveID: "CVE-2024-1111", Cvss3Score: 6.5}},
					"mitre": {{CveID: "CVE-2024-1111", Cvss3Score: 7.2}},
				},
				AffectedPackages: []pkgscanner.AffectedPackage{
					{Name: "openssl"},
				},
			},
		},
	}

	Update(result)

	if v := testutil.ToFloat64(totalPackagesWithUpdate); v != 1 {
		t.Errorf("expected 1 package with update, got %f", v)
	}

	// Should use best score (7.2 from mitre)
	v := testutil.ToFloat64(generalCVEDetails.WithLabelValues("openssl", "CVE-2024-1111", "7.2"))
	if v != 7.2 {
		t.Errorf("expected best score 7.2, got %f", v)
	}
}

func TestUpdate_RPMKernelPackage(t *testing.T) {
	result := &pkgscanner.ScanResult{
		Packages: pkgscanner.Packages{
			"kernel-core": {Name: "kernel-core", Version: "5.14.0-1", NewVersion: "5.14.0-2"},
		},
		ScannedCves: map[string]pkgscanner.VulnInfo{
			"CVE-2024-7777": {
				CveID: "CVE-2024-7777",
				CveContents: map[string][]pkgscanner.CveContent{
					"nvd": {{CveID: "CVE-2024-7777", Cvss3Score: 5.5}},
				},
				AffectedPackages: []pkgscanner.AffectedPackage{
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
	result := &pkgscanner.ScanResult{
		Packages:    pkgscanner.Packages{},
		ScannedCves: map[string]pkgscanner.VulnInfo{},
	}

	Update(result)

	if v := testutil.ToFloat64(totalPackagesWithUpdate); v != 0 {
		t.Errorf("expected 0 packages with updates, got %f", v)
	}
	if v := testutil.ToFloat64(kernelUpdateAvailable); v != 0 {
		t.Errorf("expected kernel update available = 0, got %f", v)
	}
}

func TestIsKernelPackage(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"linux-image-6.1.0-23-amd64", true},
		{"linux-image-amd64", true},
		{"linux-headers-6.1.0-23-amd64", true},
		{"linux-headers-amd64", true},
		{"kernel", true},
		{"kernel-core", true},
		{"kernel-modules", true},
		{"kernel-devel", true},
		{"openssl", false},
		{"bash", false},
		{"linux-firmware", false},
		{"kernelshark", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isKernelPackage(tt.name); got != tt.expected {
				t.Errorf("isKernelPackage(%q) = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}
}

func TestBestCVSS3Score(t *testing.T) {
	tests := []struct {
		name     string
		vuln     pkgscanner.VulnInfo
		expected float64
	}{
		{
			name:     "empty contents",
			vuln:     pkgscanner.VulnInfo{},
			expected: 0,
		},
		{
			name: "single source single score",
			vuln: pkgscanner.VulnInfo{
				CveContents: map[string][]pkgscanner.CveContent{
					"nvd": {{Cvss3Score: 7.5}},
				},
			},
			expected: 7.5,
		},
		{
			name: "multiple sources picks highest",
			vuln: pkgscanner.VulnInfo{
				CveContents: map[string][]pkgscanner.CveContent{
					"nvd":   {{Cvss3Score: 6.5}},
					"mitre": {{Cvss3Score: 8.1}},
				},
			},
			expected: 8.1,
		},
		{
			name: "multiple entries in same source",
			vuln: pkgscanner.VulnInfo{
				CveContents: map[string][]pkgscanner.CveContent{
					"nvd": {
						{Cvss3Score: 3.0},
						{Cvss3Score: 9.8},
						{Cvss3Score: 5.5},
					},
				},
			},
			expected: 9.8,
		},
		{
			name: "all zero scores",
			vuln: pkgscanner.VulnInfo{
				CveContents: map[string][]pkgscanner.CveContent{
					"nvd": {{Cvss3Score: 0}},
				},
			},
			expected: 0,
		},
		{
			name: "nil contents map",
			vuln: pkgscanner.VulnInfo{
				CveContents: nil,
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bestCVSS3Score(tt.vuln); got != tt.expected {
				t.Errorf("bestCVSS3Score() = %f, want %f", got, tt.expected)
			}
		})
	}
}
