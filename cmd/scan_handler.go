package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"security-exporter/internal/collector"
	"security-exporter/internal/pkgscanner"
	"security-exporter/internal/prommetrics"
)

// ScanResponse is the JSON response from the /scan endpoint.
type ScanResponse struct {
	Success               bool   `json:"success"`
	TotalCVEs             int    `json:"total_cves"`
	CriticalCVEs          int    `json:"critical_cves"`
	HighCVEs              int    `json:"high_cves"`
	MediumCVEs            int    `json:"medium_cves"`
	LowCVEs               int    `json:"low_cves"`
	PackagesWithUpdates   int    `json:"packages_with_updates"`
	KernelUpdateAvailable bool   `json:"kernel_update_available"`
	PreviousTotalCVEs     int    `json:"previous_total_cves"`
	CVEsFixed             int    `json:"cves_fixed"`
	CriticalCVEsFixed     int    `json:"critical_cves_fixed"`
	HighCVEsFixed         int    `json:"high_cves_fixed"`
	MediumCVEsFixed       int    `json:"medium_cves_fixed"`
	LowCVEsFixed          int    `json:"low_cves_fixed"`
	Error                 string `json:"error,omitempty"`
}

// CVSS3 severity thresholds.
const (
	cvssThresholdCritical = 9.0
	cvssThresholdHigh     = 7.0
	cvssThresholdMedium   = 4.0
)

func newScanHandler(sc *pkgscanner.Scanner, coll collector.Collector, ss *scanState) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ss.mu.Lock()
		defer ss.mu.Unlock()

		ctx, cancel := context.WithTimeout(r.Context(), scanTimeout)
		defer cancel()

		result, err := executeScan(ctx, sc, coll)
		if err != nil {
			writeJSON(w, http.StatusOK, ScanResponse{
				Success:           false,
				PreviousTotalCVEs: ss.previous.total,
				Error:             err.Error(),
			})
			return
		}

		resp := buildScanResponse(result, ss.previous)
		ss.previous = countSeverities(result)

		writeJSON(w, http.StatusOK, resp)
	})
}

func countSeverities(result *pkgscanner.ScanResult) severityCounts {
	var sc severityCounts
	sc.total = len(result.ScannedCves)
	for _, vuln := range result.ScannedCves {
		score := prommetrics.BestCVSS3Score(vuln)
		switch {
		case score >= cvssThresholdCritical:
			sc.critical++
		case score >= cvssThresholdHigh:
			sc.high++
		case score >= cvssThresholdMedium:
			sc.medium++
		default:
			sc.low++
		}
	}
	return sc
}

func floorZero(v int) int {
	if v < 0 {
		return 0
	}
	return v
}

func buildScanResponse(result *pkgscanner.ScanResult, prev severityCounts) ScanResponse {
	cur := countSeverities(result)

	packagesWithUpdates := 0
	kernelUpdate := false
	for _, pkg := range result.Packages {
		if pkg.NewVersion != "" {
			packagesWithUpdates++
			if isKernelPkg(pkg.Name) {
				kernelUpdate = true
			}
		}
	}

	return ScanResponse{
		Success:               true,
		TotalCVEs:             cur.total,
		CriticalCVEs:          cur.critical,
		HighCVEs:              cur.high,
		MediumCVEs:            cur.medium,
		LowCVEs:               cur.low,
		PackagesWithUpdates:   packagesWithUpdates,
		KernelUpdateAvailable: kernelUpdate,
		PreviousTotalCVEs:     prev.total,
		CVEsFixed:             floorZero(prev.total - cur.total),
		CriticalCVEsFixed:     floorZero(prev.critical - cur.critical),
		HighCVEsFixed:         floorZero(prev.high - cur.high),
		MediumCVEsFixed:       floorZero(prev.medium - cur.medium),
		LowCVEsFixed:          floorZero(prev.low - cur.low),
	}
}

func isKernelPkg(name string) bool {
	return strings.HasPrefix(name, "linux-image") ||
		strings.HasPrefix(name, "linux-headers") ||
		name == "kernel" ||
		strings.HasPrefix(name, "kernel-")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to write JSON response", "error", err)
	}
}
