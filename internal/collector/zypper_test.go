package collector

import (
	"testing"
)

func TestParseZypperListUpdates(t *testing.T) {
	input := `S | Repository         | Name         | Current Version  | Available Version | Arch
--+--------------------+--------------+------------------+-------------------+-------
v | SLES15-SP5-Updates | bash         | 4.4-150400.25.1  | 4.4-150400.27.1   | x86_64
v | SLES15-SP5-Updates | openssl-1_1  | 1.1.1l-150400.7.1 | 1.1.1l-150400.7.5 | x86_64
`

	updates := parseZypperListUpdates(input)

	if len(updates) != 2 {
		t.Fatalf("expected 2 updates, got %d: %v", len(updates), updates)
	}
	if v := updates["bash"]; v != "4.4-150400.27.1" {
		t.Errorf("bash version = %q, want %q", v, "4.4-150400.27.1")
	}
	if v := updates["openssl-1_1"]; v != "1.1.1l-150400.7.5" {
		t.Errorf("openssl-1_1 version = %q, want %q", v, "1.1.1l-150400.7.5")
	}
}

func TestParseZypperListUpdatesEmpty(t *testing.T) {
	updates := parseZypperListUpdates("")
	if len(updates) != 0 {
		t.Errorf("expected 0 updates, got %d", len(updates))
	}
}

func TestParseZypperListUpdatesHeaderOnly(t *testing.T) {
	input := `S | Repository | Name | Current Version | Available Version | Arch
--+------------+------+-----------------+-------------------+------
`
	updates := parseZypperListUpdates(input)
	if len(updates) != 0 {
		t.Errorf("expected 0 updates from header-only output, got %d", len(updates))
	}
}

func TestZypperCollector_OSFamily(t *testing.T) {
	c := &zypperCollector{family: "suse", release: "15.5"}
	if c.OSFamily() != "suse" {
		t.Errorf("expected suse, got %s", c.OSFamily())
	}
}

func TestZypperCollector_Release(t *testing.T) {
	c := &zypperCollector{family: "suse", release: "15.5"}
	if c.Release() != "15.5" {
		t.Errorf("expected 15.5, got %s", c.Release())
	}
}
