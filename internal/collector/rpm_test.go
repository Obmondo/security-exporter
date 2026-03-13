package collector

import (
	"testing"
)

func TestParseSourceRPM(t *testing.T) {
	tests := []struct {
		input       string
		wantName    string
		wantVersion string
		wantOK      bool
	}{
		{"bash-5.1.8-9.el9.src.rpm", "bash", "5.1.8-9.el9", true},
		{"systemd-libs-252-46.4.el9_5.src.rpm", "systemd-libs", "252-46.4.el9_5", true},
		{"xorg-x11-server-Xwayland-22.1.9-8.el9.src.rpm", "xorg-x11-server-Xwayland", "22.1.9-8.el9", true},
		{"(none)", "", "", false},
		{"", "", "", false},
		// Edge case: no hyphens at all
		{"nodashes.src.rpm", "", "", false},
		// Edge case: only one hyphen (no name-version-release split possible)
		{"name-1.0.src.rpm", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			name, version, ok := parseSourceRPM(tt.input)
			if ok != tt.wantOK {
				t.Fatalf("parseSourceRPM(%q): ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if name != tt.wantName {
				t.Errorf("parseSourceRPM(%q): name = %q, want %q", tt.input, name, tt.wantName)
			}
			if version != tt.wantVersion {
				t.Errorf("parseSourceRPM(%q): version = %q, want %q", tt.input, version, tt.wantVersion)
			}
		})
	}
}

func TestParseRpmOutput(t *testing.T) {
	input := `bash 0 5.1.8 9.el9 x86_64 bash-5.1.8-9.el9.src.rpm
gpg-pubkey 0 fd431d51 4ae0493b (none) (none)
systemd-libs 0 252 46.4.el9_5 x86_64 systemd-252-46.4.el9_5.src.rpm
`

	pkgs, srcPkgs, err := parseRpmOutput(input)
	if err != nil {
		t.Fatalf("parseRpmOutput: %v", err)
	}

	// Check pkgs output
	wantPkgs := "bash\tii\t0:5.1.8-9.el9\n" +
		"gpg-pubkey\tii\t0:fd431d51-4ae0493b\n" +
		"systemd-libs\tii\t0:252-46.4.el9_5\n"
	if pkgs != wantPkgs {
		t.Errorf("pkgs mismatch:\ngot:  %q\nwant: %q", pkgs, wantPkgs)
	}

	// Check srcPkgs output (gpg-pubkey should be skipped since SOURCERPM is "(none)")
	wantSrcPkgs := "bash\t5.1.8-9.el9\tbash\tii\n" +
		"systemd\t252-46.4.el9_5\tsystemd-libs\tii\n"
	if srcPkgs != wantSrcPkgs {
		t.Errorf("srcPkgs mismatch:\ngot:  %q\nwant: %q", srcPkgs, wantSrcPkgs)
	}
}

func TestParseRpmOutputEmpty(t *testing.T) {
	pkgs, srcPkgs, err := parseRpmOutput("")
	if err != nil {
		t.Fatalf("parseRpmOutput: %v", err)
	}
	if pkgs != "" {
		t.Errorf("expected empty pkgs, got %q", pkgs)
	}
	if srcPkgs != "" {
		t.Errorf("expected empty srcPkgs, got %q", srcPkgs)
	}
}

func TestParseRpmOutputBadLine(t *testing.T) {
	_, _, err := parseRpmOutput("only three fields here\n")
	if err == nil {
		t.Fatal("expected error for malformed line, got nil")
	}
}
