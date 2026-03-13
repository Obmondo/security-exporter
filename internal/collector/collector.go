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
	family, release, err := parseOSRelease("/etc/os-release")
	if err != nil {
		return nil, fmt.Errorf("detecting OS: %w", err)
	}

	slog.Info("detected OS", "family", family, "release", release)

	switch family {
	case "debian", "ubuntu":
		return &dpkgCollector{family: family, release: release}, nil
	case "rhel", "centos", "rocky", "ol", "almalinux", "fedora":
		return &rpmCollector{family: "redhat", release: release}, nil
	default:
		return nil, fmt.Errorf("unsupported OS family: %s", family)
	}
}

func parseOSRelease(path string) (family, release string, err error) {
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

	family = strings.ToLower(fields["ID"])
	release = fields["VERSION_ID"]
	if family == "" {
		return "", "", fmt.Errorf("ID not found in %s", path)
	}
	return family, release, nil
}
