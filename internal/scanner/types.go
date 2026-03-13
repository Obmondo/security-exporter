package scanner

import "strings"

// Package matches the vuls server's models.Package struct.
type Package struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Release         string `json:"release"`
	NewVersion      string `json:"newVersion"`
	NewRelease      string `json:"newRelease"`
	Arch            string `json:"arch"`
	Repository      string `json:"repository"`
	ModularityLabel string `json:"modularitylabel"`
}

// Packages matches the vuls server's models.Packages type.
type Packages map[string]Package

// ScanRequest is the payload sent to the Vuls server.
type ScanRequest struct {
	Family     string   `json:"family"`
	Release    string   `json:"release"`
	ServerName string   `json:"serverName"`
	Packages   Packages `json:"packages"`
}

// ScanResult is the response from the Vuls server.
type ScanResult struct {
	ServerName  string              `json:"serverName"`
	Family      string              `json:"family"`
	Release     string              `json:"release"`
	ScannedCves map[string]VulnInfo `json:"scannedCves"`
	Packages    Packages            `json:"packages"`
}

type VulnInfo struct {
	CveID            string                  `json:"cveID"`
	CveContents      map[string][]CveContent `json:"cveContents"`
	AffectedPackages []AffectedPackage       `json:"affectedPackages"`
}

type CveContent struct {
	CveID      string  `json:"cveID"`
	Cvss3Score float64 `json:"cvss3Score"`
}

type AffectedPackage struct {
	Name        string `json:"name"`
	NotFixedYet bool   `json:"notFixedYet"`
}

// ParsePackages splits tab-separated "name\tversion" lines into a Packages map.
func ParsePackages(raw string) Packages {
	pkgs := make(Packages)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		const expectedFields = 2
		parts := strings.SplitN(line, "\t", expectedFields)
		name := parts[0]
		version := ""
		if len(parts) == expectedFields {
			version = parts[1]
		}
		pkgs[name] = Package{
			Name:    name,
			Version: version,
		}
	}
	return pkgs
}
