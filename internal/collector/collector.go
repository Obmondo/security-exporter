package collector

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

type Collector interface {
	CollectPackages(ctx context.Context) (pkgs, srcPkgs string, err error)
	AvailableUpdates(ctx context.Context) (map[string]string, error)
	OSFamily() string
	Release() string
}

func New() (Collector, error) {
	id, versionID, err := DetectOS()
	if err != nil {
		return nil, fmt.Errorf("detecting OS: %w", err)
	}

	slog.Info("detected OS", "id", id, "version", versionID)

	switch id {
	case "debian", "ubuntu":
		return &dpkgCollector{family: id, release: versionID}, nil
	case "rhel", "centos", "rocky", "ol", "almalinux", "fedora":
		return &rpmCollector{family: "redhat", release: versionID}, nil
	case "sles", "suse":
		return &zypperCollector{family: "suse.linux.enterprise.server", release: versionID}, nil
	default:
		return nil, fmt.Errorf("unsupported OS family: %s", id)
	}
}

// DetectOS reads /etc/os-release and returns the lowercased ID and raw
// VERSION_ID. Exported so other packages (e.g. eol metric setup) can use
// the same source of truth without duplicating the parser.
func DetectOS() (id, versionID string, err error) {
	return parseOSRelease("/etc/os-release")
}

func parseOSRelease(path string) (id, versionID string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}

	fields := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		const kvParts = 2
		parts := strings.SplitN(line, "=", kvParts)
		if len(parts) == kvParts {
			fields[parts[0]] = strings.Trim(parts[1], "\"")
		}
	}

	id = strings.ToLower(fields["ID"])
	versionID = fields["VERSION_ID"]
	if id == "" {
		return "", "", fmt.Errorf("ID not found in %s", path)
	}
	return id, versionID, nil
}
