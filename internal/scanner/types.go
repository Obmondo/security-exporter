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

// SrcPackage represents a source package and its associated binaries.
type SrcPackage struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	BinaryNames []string `json:"binaryNames"`
}

// SrcPackages maps source package names to their metadata.
type SrcPackages map[string]SrcPackage

// ScanRequest is the payload sent to the Vuls server.
type ScanRequest struct {
	Family      string      `json:"family"`
	Release     string      `json:"release"`
	ServerName  string      `json:"serverName"`
	Packages    Packages    `json:"packages"`
	SrcPackages SrcPackages `json:"srcPackages,omitempty"`
}

// ScanResult is the response from the Vuls server.
type ScanResult struct {
	ServerName  string              `json:"serverName"`
	Family      string              `json:"family"`
	Release     string              `json:"release"`
	ScannedCves map[string]VulnInfo `json:"scannedCves"`
	Packages    Packages            `json:"packages"`
	SrcPackages SrcPackages         `json:"srcPackages,omitempty"`
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

// ParseSrcPackages parses tab-separated "src-name\tsrc-version\tbinary-name" lines
// into a SrcPackages map, grouping binary names under each source package.
func ParseSrcPackages(raw string) SrcPackages {
	pkgs := make(SrcPackages)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		const expectedFields = 3
		parts := strings.SplitN(line, "\t", expectedFields)
		if len(parts) < expectedFields {
			continue
		}
		srcName := parts[0]
		srcVersion := parts[1]
		binName := parts[2]
		if srcName == "" {
			continue
		}
		sp, ok := pkgs[srcName]
		if !ok {
			sp = SrcPackage{
				Name:    srcName,
				Version: srcVersion,
			}
		}
		sp.BinaryNames = append(sp.BinaryNames, binName)
		pkgs[srcName] = sp
	}
	return pkgs
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
