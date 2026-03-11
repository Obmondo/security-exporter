package collector

import (
	"context"
	"os/exec"
)

type rpmCollector struct {
	family  string
	release string
}

func (*rpmCollector) Packages(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "rpm", "-qa", "--queryformat", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (r *rpmCollector) OSFamily() string { return r.family }
func (r *rpmCollector) Release() string  { return r.release }
