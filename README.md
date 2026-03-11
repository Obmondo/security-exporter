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
cron_expression: "0 */12 * * *"
```

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

## Build

```sh
make build
```

## Test

```sh
make test
```
