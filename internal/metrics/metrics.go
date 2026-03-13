package metrics

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"security-exporter/internal/pkgscanner"
)

var (
	totalPackagesWithUpdate = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "total_number_of_packages_with_update",
		Help: "Total number of packages that have updates available.",
	})

	generalCVEDetails = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "general_cve_details",
		Help: "CVE details for non-kernel packages.",
	}, []string{"application", "cve_id", "score"})

	kernelCVEDetails = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kernel_cve_details",
		Help: "CVE details for kernel packages.",
	}, []string{"application", "cve_id", "score"})

	kernelUpdateAvailable = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "kernel_update_available",
		Help: "Whether a kernel update is available (1 = yes, 0 = no).",
	})
)

func Update(result *pkgscanner.ScanResult) {
	generalCVEDetails.Reset()
	kernelCVEDetails.Reset()

	updateCount := 0
	kernelUpdate := false

	for _, pkg := range result.Packages {
		if pkg.NewVersion != "" {
			updateCount++
			if isKernelPackage(pkg.Name) {
				kernelUpdate = true
			}
		}
	}
	totalPackagesWithUpdate.Set(float64(updateCount))

	if kernelUpdate {
		kernelUpdateAvailable.Set(1)
	} else {
		kernelUpdateAvailable.Set(0)
	}

	slog.Info("updating metrics", "packages_with_updates", updateCount, "cves", len(result.ScannedCves))

	for _, vuln := range result.ScannedCves {
		score := bestCVSS3Score(vuln)
		scoreStr := fmt.Sprintf("%.1f", score)

		for _, pkg := range vuln.AffectedPackages {
			gauge := generalCVEDetails
			if isKernelPackage(pkg.Name) {
				gauge = kernelCVEDetails
			}
			gauge.WithLabelValues(pkg.Name, vuln.CveID, scoreStr).Set(score)
		}
	}
}

func isKernelPackage(name string) bool {
	return strings.HasPrefix(name, "linux-image") ||
		strings.HasPrefix(name, "linux-headers") ||
		name == "kernel" ||
		strings.HasPrefix(name, "kernel-")
}

func bestCVSS3Score(v pkgscanner.VulnInfo) float64 {
	var best float64
	for _, contents := range v.CveContents {
		for _, c := range contents {
			if c.Cvss3Score > best {
				best = c.Cvss3Score
			}
		}
	}
	return best
}
