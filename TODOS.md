# Security Exporter — TODOs

From CEO Plan Review (2026-03-16), HOLD SCOPE mode.

## Completed

### Decision 1: Add scan health metrics [S]

**Completed:** feat/scan-observability (2026-03-16)

Added `security_exporter_last_scan_timestamp` (gauge), `security_exporter_scan_errors_total` (counter), and `security_exporter_scan_duration_seconds` (gauge) to `internal/prommetrics/`. Wired into `scanTask()` in `cmd/serve.go`.

---

### Decision 2: Use gocron StartImmediately [S]

**Completed:** Already implemented before this review.

---

### Decision 3: Implement RPM AvailableUpdates [M]

**Completed:** feat/scan-observability (2026-03-16)

Implemented `AvailableUpdates()` for RPM via `dnf check-update` with `yum` fallback. Parses exit code 100 (updates available) and output format. Includes 4 parser tests.

---

### Decision 4: Add scan duration metric [S]

**Completed:** feat/scan-observability (2026-03-16)

Bundled with Decision 1 — `security_exporter_scan_duration_seconds` gauge set after each scan.
