package collector

import (
	"context"
	"fmt"
	"os"
	"strings"
)

type Collector interface {
	Packages(ctx context.Context) (string, error)
	OSFamily() string
	Release() string
}

func New() (Collector, error) {
	family, release, err := parseOSRelease("/etc/os-release")
	if err != nil {
		return nil, fmt.Errorf("detecting OS: %w", err)
	}

	switch family {
	case "debian", "ubuntu":
		return &dpkgCollector{family: "debian", release: release}, nil
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
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
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
