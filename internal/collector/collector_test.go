package collector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseOSRelease_Debian(t *testing.T) {
	content := `ID=debian
VERSION_ID="12"
`
	path := writeTempFile(t, content)
	family, release, err := parseOSRelease(path)
	if err != nil {
		t.Fatal(err)
	}
	if family != "debian" {
		t.Errorf("expected family debian, got %s", family)
	}
	if release != "12" {
		t.Errorf("expected release 12, got %s", release)
	}
}

func TestParseOSRelease_Ubuntu(t *testing.T) {
	content := `ID=ubuntu
VERSION_ID="22.04"
`
	path := writeTempFile(t, content)
	family, release, err := parseOSRelease(path)
	if err != nil {
		t.Fatal(err)
	}
	if family != "ubuntu" {
		t.Errorf("expected family ubuntu, got %s", family)
	}
	if release != "22.04" {
		t.Errorf("expected release 22.04, got %s", release)
	}
}

func TestParseOSRelease_Rocky(t *testing.T) {
	content := `ID="rocky"
VERSION_ID="9.3"
`
	path := writeTempFile(t, content)
	family, release, err := parseOSRelease(path)
	if err != nil {
		t.Fatal(err)
	}
	if family != "rocky" {
		t.Errorf("expected family rocky, got %s", family)
	}
	if release != "9.3" {
		t.Errorf("expected release 9.3, got %s", release)
	}
}

func TestParseOSRelease_MissingID(t *testing.T) {
	content := `VERSION_ID="12"
`
	path := writeTempFile(t, content)
	_, _, err := parseOSRelease(path)
	if err == nil {
		t.Fatal("expected error for missing ID")
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
