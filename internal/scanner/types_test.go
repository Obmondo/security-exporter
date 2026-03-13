package scanner

import (
	"strings"
	"testing"
)

func TestParseSrcPackages(t *testing.T) {
	raw := "bash\t5.2.21-2ubuntu4\tbash\tii \n" +
		"bash\t5.2.21-2ubuntu4\tbash-builtins\tii \n" +
		"openssl\t3.0.13-0ubuntu3\tlibssl3\tii \n" +
		"openssl\t3.0.13-0ubuntu3\topenssl\tii \n"

	got := ParseSrcPackages(raw)

	if len(got) != 2 {
		t.Fatalf("expected 2 source packages, got %d", len(got))
	}

	bash, ok := got["bash"]
	if !ok {
		t.Fatal("expected bash source package")
	}
	if bash.Version != "5.2.21-2ubuntu4" {
		t.Errorf("expected bash version 5.2.21-2ubuntu4, got %s", bash.Version)
	}
	if len(bash.BinaryNames) != 2 {
		t.Errorf("expected 2 binaries for bash, got %d", len(bash.BinaryNames))
	}

	ssl, ok := got["openssl"]
	if !ok {
		t.Fatal("expected openssl source package")
	}
	if len(ssl.BinaryNames) != 2 {
		t.Errorf("expected 2 binaries for openssl, got %d", len(ssl.BinaryNames))
	}
}

func TestParseSrcPackages_Empty(t *testing.T) {
	got := ParseSrcPackages("")
	if len(got) != 0 {
		t.Errorf("expected 0 source packages for empty input, got %d", len(got))
	}
}

func TestParseSrcPackages_MalformedLines(t *testing.T) {
	raw := "onlyone\n" +
		"two\tfields\n" +
		"three\tfields\tonly\n" +
		"good\t1.0\tbinary\tii \n"

	got := ParseSrcPackages(raw)
	if len(got) != 1 {
		t.Fatalf("expected 1 source package, got %d", len(got))
	}
	if _, ok := got["good"]; !ok {
		t.Error("expected 'good' source package")
	}
}

func TestParseSrcPackages_StripsArch(t *testing.T) {
	raw := "openssl\t3.0.13\tlibssl3:amd64\tii \nopenssl\t3.0.13\topenssl\tii \n"
	got := ParseSrcPackages(raw)
	sp, ok := got["openssl"]
	if !ok {
		t.Fatal("expected openssl source package")
	}
	if len(sp.BinaryNames) != 2 {
		t.Fatalf("expected 2 binaries for openssl, got %d", len(sp.BinaryNames))
	}
	for _, bn := range sp.BinaryNames {
		if strings.Contains(bn, ":") {
			t.Errorf("binary name should not contain arch qualifier: %s", bn)
		}
	}
}

func TestParseSrcPackages_FiltersNonInstalled(t *testing.T) {
	raw := "bash\t5.2\tbash\tii \n" +
		"removed-pkg\t1.0\tremoved-bin\trc \n" +
		"halfinstall\t2.0\thalf-bin\tiH \n" +
		"openssl\t3.0\topenssl\tii \n"

	got := ParseSrcPackages(raw)
	if len(got) != 2 {
		t.Fatalf("expected 2 source packages, got %d", len(got))
	}
	if _, ok := got["bash"]; !ok {
		t.Error("expected bash source package")
	}
	if _, ok := got["openssl"]; !ok {
		t.Error("expected openssl source package")
	}
	if _, ok := got["removed-pkg"]; ok {
		t.Error("removed-pkg should have been filtered out")
	}
	if _, ok := got["halfinstall"]; ok {
		t.Error("halfinstall should have been filtered out")
	}
}

func TestParsePackages(t *testing.T) {
	raw := "bash\tii \t5.2\nopenssl\tii \t3.0.13-1\n"
	got := ParsePackages(raw)
	if len(got) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(got))
	}
	if got["bash"].Version != "5.2" {
		t.Errorf("expected bash version 5.2, got %s", got["bash"].Version)
	}
}

func TestParsePackages_FiltersNonInstalled(t *testing.T) {
	raw := "bash\tii \t5.2\n" +
		"removed-pkg\trc \t1.0\n" +
		"halfinstall\tiH \t2.0\n" +
		"unknown\tun \t\n" +
		"openssl\tii \t3.0.13\n"

	got := ParsePackages(raw)
	if len(got) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(got))
	}
	if _, ok := got["bash"]; !ok {
		t.Error("expected bash")
	}
	if _, ok := got["openssl"]; !ok {
		t.Error("expected openssl")
	}
	if _, ok := got["removed-pkg"]; ok {
		t.Error("removed-pkg should have been filtered out")
	}
	if _, ok := got["halfinstall"]; ok {
		t.Error("halfinstall should have been filtered out")
	}
	if _, ok := got["unknown"]; ok {
		t.Error("unknown should have been filtered out")
	}
}

func TestParsePackages_MalformedLines(t *testing.T) {
	raw := "onlyone\n" +
		"two\tfields\n" +
		"good\tii \t1.0\n"

	got := ParsePackages(raw)
	if len(got) != 1 {
		t.Fatalf("expected 1 package, got %d", len(got))
	}
	if _, ok := got["good"]; !ok {
		t.Error("expected 'good' package")
	}
}
