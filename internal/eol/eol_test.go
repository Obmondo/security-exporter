package eol

import (
	"testing"
)

// TestLookup_Logic exercises all lookup paths (exact match, major-version
// fallback, slug remap, miss cases) against a hand-built fixture so the
// assertions stay stable when the real data.json refreshes.
func TestLookup_Logic(t *testing.T) {
	orig := table
	t.Cleanup(func() { table = orig })

	table = map[string][]Entry{
		"ubuntu": {
			{Cycle: "24.04", Support: "2029-05-31", EOL: "2029-05-31", Extended: "2036-05-31"},
			{Cycle: "22.04", Support: "2027-06-01", EOL: "2027-06-01", Extended: "2032-04-30"},
		},
		"rhel": {
			{Cycle: "9", Support: "2027-05-31", EOL: "2032-05-31", Extended: "2035-05-31"},
		},
		"debian": {
			{Cycle: "12", EOL: "2028-06-10", Extended: "2030-06-30"},
		},
		"fedora": {
			{Cycle: "43", EOL: "2026-12-09"},
		},
		"sles": {
			{Cycle: "15.7", EOL: "2031-07-31", Extended: "2034-07-31"},
		},
		"oracle-linux": {
			{Cycle: "10"},
		},
	}

	tests := []struct {
		name    string
		id      string
		version string
		wantOK  bool
		wantSet [3]bool // support, eol, extended
	}{
		{"ubuntu LTS exact match", "ubuntu", "24.04", true, [3]bool{true, true, true}},
		{"case-insensitive ID", "Ubuntu", "24.04", true, [3]bool{true, true, true}},
		{"rhel major-version fallback from 9.3", "rhel", "9.3", true, [3]bool{true, true, true}},
		{"debian has no support phase", "debian", "12", true, [3]bool{false, true, true}},
		{"fedora has only EOL", "fedora", "43", true, [3]bool{false, true, false}},
		{"suse remaps to sles slug", "suse", "15.7", true, [3]bool{false, true, true}},
		{"unknown version", "ubuntu", "9999", false, [3]bool{}},
		{"unknown distro", "notadistro", "1", false, [3]bool{}},
		{"cycle exists but no dates", "ol", "10", false, [3]bool{}},
		{"empty version", "ubuntu", "", false, [3]bool{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Lookup(tt.id, tt.version)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (phases %+v)", ok, tt.wantOK, got)
			}
			if !ok {
				return
			}
			if got.Support.IsZero() == tt.wantSet[0] {
				t.Errorf("Support set = %v, want %v", !got.Support.IsZero(), tt.wantSet[0])
			}
			if got.EOL.IsZero() == tt.wantSet[1] {
				t.Errorf("EOL set = %v, want %v", !got.EOL.IsZero(), tt.wantSet[1])
			}
			if got.Extended.IsZero() == tt.wantSet[2] {
				t.Errorf("Extended set = %v, want %v", !got.Extended.IsZero(), tt.wantSet[2])
			}
		})
	}
}

// TestEmbeddedData_Smoke verifies the generated data.json parses and
// carries entries for every product slug the runtime maps.
func TestEmbeddedData_Smoke(t *testing.T) {
	seen := map[string]bool{}
	for _, slug := range productBySlug {
		seen[slug] = true
	}
	for slug := range seen {
		entries, ok := table[slug]
		if !ok {
			t.Errorf("embedded data missing product %q (did gen-eol run?)", slug)
			continue
		}
		if len(entries) == 0 {
			t.Errorf("embedded data has zero cycles for %q", slug)
		}
	}
}
