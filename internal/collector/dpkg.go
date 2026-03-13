package collector

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type dpkgCollector struct {
	family  string
	release string
}

func (*dpkgCollector) Packages(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f", "${Package}\t${Version}\n")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (*dpkgCollector) SrcPackages(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f", "${source:Package}\t${source:Version}\t${binary:Package}\n")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (*dpkgCollector) AvailableUpdates(ctx context.Context) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, "apt", "list", "--upgradable")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running apt list --upgradable: %w", err)
	}

	const minFields = 2 // suite, version
	updates := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Listing...") {
			continue
		}
		// Format: "package/suite version arch [upgradable from: old-version]"
		slashIdx := strings.Index(line, "/")
		if slashIdx < 0 {
			continue
		}
		name := line[:slashIdx]
		rest := line[slashIdx+1:]
		fields := strings.Fields(rest)
		if len(fields) < minFields {
			continue
		}
		updates[name] = fields[1]
	}
	return updates, nil
}

func (d *dpkgCollector) OSFamily() string { return d.family }
func (d *dpkgCollector) Release() string  { return d.release }
