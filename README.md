# Security Exporter

[![Test](https://github.com/Obmondo/security-exporter/actions/workflows/test.yaml/badge.svg)](https://github.com/Obmondo/security-exporter/actions/workflows/test.yaml)
[![Lint](https://github.com/Obmondo/security-exporter/actions/workflows/lint.yaml/badge.svg)](https://github.com/Obmondo/security-exporter/actions/workflows/lint.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Obmondo/security-exporter)](https://goreportcard.com/report/github.com/Obmondo/security-exporter)

Prometheus exporter that collects installed packages, sends them to a Vuls server for vulnerability scanning, and exposes CVE metrics.

## Configuration

See `config/config.yaml` for an example configuration file.

```yaml
vuls_server:
  url: "https://vuls.obmondo.com"
  timeout: 30s
  cert_file: "/etc/puppetlabs/puppet/ssl/certs/<certname>.pem"
  key_file: "/etc/puppetlabs/puppet/ssl/private_keys/<certname>.pem"
  ca_file: "/etc/puppetlabs/puppet/ssl/certs/ca.pem"
listen_address: "127.254.254.254:63396"
scan_interval: 12h
```

| Field | Description |
|-------|-------------|
| `vuls_server.url` | URL of the Vuls server |
| `vuls_server.timeout` | HTTP request timeout (Go duration) |
| `vuls_server.cert_file` | Client certificate for mTLS (optional) |
| `vuls_server.key_file` | Client key for mTLS (optional) |
| `vuls_server.ca_file` | CA certificate for mTLS (optional) |
| `listen_address` | Address to serve Prometheus metrics on |
| `scan_interval` | How often to scan and push results (Go duration, e.g. `12h`, `30m`) |

## Usage

```sh
obmondo-security-exporter -config /etc/obmondo/security-exporter/config.yaml
```

## Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `total_number_of_packages_with_update` | Gauge | — | Total packages with available updates |
| `general_cve_details` | GaugeVec | application, cve_id, score | CVE details for non-kernel packages |
| `kernel_cve_details` | GaugeVec | application, cve_id, score | CVE details for kernel packages |
| `kernel_update_available` | Gauge | — | Whether a kernel update is available (1/0) |

## Development

### Build

```sh
make build
```

### Test

```sh
make test
```

### Lint

```sh
make lint
```

### Docker Compose

Start a local Vuls stack (server, CVE DB, OVAL DB) with the exporter:

```sh
make docker-up
```

This starts:
- `vuls-server` — Vuls scan server on port 5515
- `vuls-db` — go-cve-dictionary (NVD fetch + server)
- `vuls-oval-db` — goval-dictionary (Debian 12, Ubuntu 22.04/24.04)
- `security-exporter` — the exporter, metrics on port 63396

The first start takes a while as NVD and OVAL data is fetched.

```sh
make docker-logs    # follow logs
make docker-down    # stop and remove containers
```

## Release

Releases are managed via [GoReleaser](https://goreleaser.com/).

- **Gitea** — tag push triggers `.gitea/workflows/release.yaml`, which builds deb/rpm packages via `.goreleaser-gitea.yaml` and uploads them to the package signing server.
- **GitHub** — tag push triggers `.github/workflows/release.yaml`, which creates a GitHub release with changelog and tarballs via `.goreleaser-github.yaml`.

To create a release:

```sh
git tag v1.0.0
git push origin v1.0.0
```
