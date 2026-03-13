package scanner

import (
	"testing"
)

func TestParseSrcPackages(t *testing.T) {
	raw := "bash\t5.2.21-2ubuntu4\tbash\n" +
		"bash\t5.2.21-2ubuntu4\tbash-builtins\n" +
		"openssl\t3.0.13-0ubuntu3\tlibssl3\n" +
		"openssl\t3.0.13-0ubuntu3\topenssl\n"

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
		"good\t1.0\tbinary\n"

	got := ParseSrcPackages(raw)
	if len(got) != 1 {
		t.Fatalf("expected 1 source package, got %d", len(got))
	}
	if _, ok := got["good"]; !ok {
		t.Error("expected 'good' source package")
	}
}

func TestParsePackages(t *testing.T) {
	raw := "bash\t5.2\nopenssl\t3.0.13-1\n"
	got := ParsePackages(raw)
	if len(got) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(got))
	}
	if got["bash"].Version != "5.2" {
		t.Errorf("expected bash version 5.2, got %s", got["bash"].Version)
	}
}
