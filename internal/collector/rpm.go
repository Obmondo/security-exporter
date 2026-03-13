package collector

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type rpmCollector struct {
	family  string
	release string
}

func (*rpmCollector) CollectPackages(ctx context.Context) (string, string, error) {
	cmd := exec.CommandContext(ctx, "rpm", "-qa", "--queryformat",
		"%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{ARCH} %{SOURCERPM}\n")
	out, err := cmd.Output()
	if err != nil {
		return "", "", err
	}
	pkgs, srcPkgs, err := parseRpmOutput(string(out))
	if err != nil {
		return "", "", err
	}
	return pkgs, srcPkgs, nil
}

func (*rpmCollector) AvailableUpdates(_ context.Context) (map[string]string, error) {
	return nil, nil
}

func (r *rpmCollector) OSFamily() string { return r.family }
func (r *rpmCollector) Release() string  { return r.release }

// parseRpmOutput parses the 6-field rpm -qa output and produces tab-separated
// strings matching the ParsePackages and ParseSrcPackages contracts.
func parseRpmOutput(raw string) (pkgs, srcPkgs string, err error) {
	lines := strings.Split(raw, "\n")
	pkgLines := make([]string, 0, len(lines))
	srcLines := make([]string, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		const rpmFieldCount = 6 // NAME EPOCHNUM VERSION RELEASE ARCH SOURCERPM
		if len(fields) != rpmFieldCount {
			return "", "", fmt.Errorf("unexpected rpm output line (got %d fields, want %d): %q", len(fields), rpmFieldCount, line)
		}
		name := fields[0]
		epoch := fields[1]
		version := fields[2]
		release := fields[3]
		// fields[4] is ARCH (unused for pkgs line)
		sourceRPM := fields[5]

		// pkgs: name\tii\tepoch:version-release
		pkgLines = append(pkgLines, fmt.Sprintf("%s\tii\t%s:%s-%s", name, epoch, version, release))

		// srcPkgs: srcName\tsrcVersion\tbinaryName\tii
		if srcName, srcVer, ok := parseSourceRPM(sourceRPM); ok {
			srcLines = append(srcLines, fmt.Sprintf("%s\t%s\t%s\tii", srcName, srcVer, name))
		}
	}

	pkgs = strings.Join(pkgLines, "\n")
	if len(pkgLines) > 0 {
		pkgs += "\n"
	}
	srcPkgs = strings.Join(srcLines, "\n")
	if len(srcLines) > 0 {
		srcPkgs += "\n"
	}
	return pkgs, srcPkgs, nil
}

// parseSourceRPM extracts the source package name and version from a SOURCERPM
// field value like "bash-5.1.8-9.el9.src.rpm". It returns false for "(none)"
// or empty values (e.g. GPG keys have no source RPM).
func parseSourceRPM(s string) (name, version string, ok bool) {
	if s == "" || s == "(none)" {
		return "", "", false
	}

	// Strip .src.rpm suffix
	s = strings.TrimSuffix(s, ".src.rpm")

	// NVR format: name-version-release (name can contain hyphens)
	// Find the last two hyphens to split.
	releaseIdx := strings.LastIndex(s, "-")
	if releaseIdx <= 0 {
		return "", "", false
	}
	nameVersion := s[:releaseIdx]
	release := s[releaseIdx+1:]

	versionIdx := strings.LastIndex(nameVersion, "-")
	if versionIdx <= 0 {
		return "", "", false
	}
	name = nameVersion[:versionIdx]
	ver := nameVersion[versionIdx+1:]

	return name, ver + "-" + release, true
}
