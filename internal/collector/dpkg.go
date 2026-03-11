package collector

import (
	"context"
	"os/exec"
)

type dpkgCollector struct {
	family  string
	release string
}

func (d *dpkgCollector) Packages(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f", "${Package}\t${Version}\n")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (d *dpkgCollector) OSFamily() string { return d.family }
func (d *dpkgCollector) Release() string  { return d.release }
