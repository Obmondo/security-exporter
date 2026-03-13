package collector

import (
	"context"
	"os/exec"
)

type rpmCollector struct {
	family  string
	release string
}

func (*rpmCollector) CollectPackages(ctx context.Context) (string, string, error) {
	cmd := exec.CommandContext(ctx, "rpm", "-qa", "--queryformat", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n")
	out, err := cmd.Output()
	if err != nil {
		return "", "", err
	}
	return string(out), "", nil
}

func (*rpmCollector) AvailableUpdates(_ context.Context) (map[string]string, error) {
	return nil, nil
}

func (r *rpmCollector) OSFamily() string { return r.family }
func (r *rpmCollector) Release() string  { return r.release }
