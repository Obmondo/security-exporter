package scanner

// ScanRequest is the payload sent to the Vuls server.
type ScanRequest struct {
	Family     string `json:"family"`
	Release    string `json:"release"`
	ServerName string `json:"serverName"`
	Packages   string `json:"packages"`
}

// ScanResult is the response from the Vuls server.
type ScanResult struct {
	ServerName  string                 `json:"serverName"`
	Family      string                 `json:"family"`
	Release     string                 `json:"release"`
	ScannedCves map[string]VulnInfo    `json:"scannedCves"`
	Packages    map[string]PackageInfo `json:"packages"`
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

type PackageInfo struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	NewVersion string `json:"newVersion"`
}
