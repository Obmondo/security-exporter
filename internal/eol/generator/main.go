// Command generator refreshes internal/eol/data.json from endoflife.date.
//
// It fetches lifecycle JSON for each supported Linux distro product and
// writes a trimmed set of support/eol/extended dates per cycle.
//
// Tolerant of partial failures: a product that fails to fetch keeps its
// previous entries (if data.json exists). Exits non-zero only when every
// product fails, so stale checked-in data can still drive a build.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"security-exporter/internal/eol"
)

const (
	apiBase         = "https://endoflife.date/api"
	fetchTimeout    = 30 * time.Second
	maxResponseSize = 5 << 20 // 5 MiB
	dateLayout      = "2006-01-02"
	outputFilename  = "data.json"
	outputFileMode  = 0o644
)

// products is the ordered list of endoflife.date product slugs to fetch.
// Must stay aligned with productBySlug in eol.go — opensuse is fetched
// for data completeness even though no /etc/os-release ID maps to it yet.
var products = []string{
	"debian",
	"ubuntu",
	"rhel",
	"centos",
	"rocky-linux",
	"oracle-linux",
	"almalinux",
	"fedora",
	"sles",
	"opensuse",
}

// apiCycle mirrors the relevant fields of an endoflife.date cycle entry.
// support/eol/extendedSupport can each be a date string or bool false.
type apiCycle struct {
	Cycle           string          `json:"cycle"`
	Support         json.RawMessage `json:"support,omitempty"`
	EOL             json.RawMessage `json:"eol,omitempty"`
	ExtendedSupport json.RawMessage `json:"extendedSupport,omitempty"`
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("eol-gen: ")

	wd, err := os.Getwd()
	if err != nil {
		log.Fatalf("resolve output dir: %v", err)
	}
	outPath := filepath.Join(wd, outputFilename)

	existing := loadExisting(outPath)
	fresh := make(map[string][]eol.Entry, len(products))
	failures := 0

	client := &http.Client{Timeout: fetchTimeout}
	for _, product := range products {
		entries, err := fetchProduct(client, product)
		if err != nil {
			failures++
			log.Printf("fetch %s: %v (keeping previous entries)", product, err)
			if prev, ok := existing[product]; ok {
				fresh[product] = prev
			}
			continue
		}
		fresh[product] = entries
		log.Printf("fetched %s: %d cycles", product, len(entries))
	}

	if failures == len(products) {
		log.Fatalf("all %d products failed to fetch; leaving %s untouched", failures, outPath)
	}

	if err := writeJSON(outPath, fresh); err != nil {
		log.Fatalf("write %s: %v", outPath, err)
	}
	log.Printf("wrote %s (%d products, %d failures)", outPath, len(fresh), failures)
}

func loadExisting(path string) map[string][]eol.Entry {
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("read existing %s: %v (starting fresh)", path, err)
		}
		return map[string][]eol.Entry{}
	}
	var out map[string][]eol.Entry
	if err := json.Unmarshal(data, &out); err != nil {
		log.Printf("parse existing %s: %v (starting fresh)", path, err)
		return map[string][]eol.Entry{}
	}
	if out == nil {
		return map[string][]eol.Entry{}
	}
	return out
}

func fetchProduct(client *http.Client, slug string) ([]eol.Entry, error) {
	url := fmt.Sprintf("%s/%s.json", apiBase, slug)
	resp, err := client.Get(url) //nolint:noctx // short-lived generator, client timeout suffices
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var raw []apiCycle
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	entries := make([]eol.Entry, 0, len(raw))
	for _, c := range raw {
		entries = append(entries, eol.Entry{
			Cycle:    c.Cycle,
			Support:  parseMaybeDate(c.Support),
			EOL:      parseMaybeDate(c.EOL),
			Extended: parseMaybeDate(c.ExtendedSupport),
		})
	}
	return entries, nil
}

// parseMaybeDate returns the canonical YYYY-MM-DD string if the JSON value
// is a parseable date, or "" otherwise (covers missing, bool false, and
// malformed values).
func parseMaybeDate(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	if _, err := time.Parse(dateLayout, s); err != nil {
		return ""
	}
	return s
}

func writeJSON(path string, data map[string][]eol.Entry) error {
	buf, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	buf = append(buf, '\n')
	return os.WriteFile(path, buf, outputFileMode)
}
