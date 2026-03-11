# Security Exporter - Claude Code Context

## Project Overview
Prometheus exporter that collects installed packages from Linux hosts, sends them to a Vuls server for vulnerability scanning, and exposes CVE metrics.

## Structure
- `cmd/main.go` — entrypoint: config loading, scheduler (gocron DurationJob), HTTP server, graceful shutdown
- `config/` — YAML config parsing with custom `Duration` type
- `internal/scanner/` — HTTP client to Vuls server, mTLS support, request/response types
- `internal/collector/` — OS detection via `/etc/os-release`, package listing via `dpkg-query` (Debian/Ubuntu) or `rpm` (RHEL/CentOS/Rocky/Alma/Fedora)
- `internal/metrics/` — Prometheus gauges: package updates, kernel updates, CVE details (general + kernel)

## Build & Test
```sh
make build      # static linux/amd64 binary → dist/
make test       # go test ./...
make vet        # go vet ./...
make lint       # golangci-lint run ./...
```

## Docker Compose
```sh
make docker-up    # vuls-server + cve-db + oval-db + exporter
make docker-down  # teardown
```

## Release
- Gitea: goreleaser with deb/rpm packages (`.goreleaser-gitea.yaml`)
- GitHub: goreleaser with changelog + tarballs only (`.goreleaser-github.yaml`)

## Conventions
- Go 1.24, module name `security-exporter`
- Structured logging via `log/slog` (JSON handler to stderr)
- Config uses Go duration strings (`30s`, `12h`) not cron expressions
- golangci-lint config in `.golangci.yaml` (version 2 format)
- Tests use `httptest` servers for scanner, temp files for config/collector
- No `Co-Authored-By` lines in commits

## Key Dependencies
- `github.com/go-co-op/gocron/v2` — scheduler
- `github.com/prometheus/client_golang` — Prometheus metrics
- `gopkg.in/yaml.v3` — config parsing
