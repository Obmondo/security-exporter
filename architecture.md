# Vuls Security Scanner - Architecture

## Overview

A vulnerability scanning pipeline that collects installed packages from remote Linux servers,
scans them against the vuls2 nightly database, and serves reports via a REST API.

The **Security Exporter** is installed on each Linux server as a lightweight Go binary.
It runs `dpkg-query` (Debian/Ubuntu) or `rpm -qa` (RHEL/CentOS) locally to collect the
installed package list and sends it to the Vuls Server hosted at `vuls.obmondo.com`.

The **Vuls Stack** runs inside a Kubernetes cluster. Vuls Server receives package payloads,
matches them against the vuls2 nightly SQLite database (CVEs, advisories, detection data),
and writes scan results with CVSS scores to a shared PVC.

The **Vuls Exporter** is a simple Go daemon deployed in the same namespace as Vuls Server
so it can mount the same PVC. It watches for new result files and pushes them to the API.

The **API** stores and serves vulnerability reports. Users can list all reports or view
a specific server's CVE report with CVSS scores.

## Architecture Diagram

```mermaid
graph LR
    subgraph Linux Server 1 - Ubuntu 22.04
        SE1[Security Exporter] -->|1. dpkg-query| N1[localhost]
    end

    subgraph Linux Server 2 - RHEL 9
        SE2[Security Exporter] -->|1. rpm -qa| N2[localhost]
    end

    subgraph Linux Server 3 - Debian
        SE3[Security Exporter] -->|1. dpkg-query| N3[localhost]
    end

    subgraph vuls.obmondo.com
        subgraph Kubernetes Cluster - same namespace
            VS[Vuls Server :5515]
            VDB[(vuls2 nightly db<br>SQLite ~7GB)]
            VE[Vuls Exporter]
            API[API :8080]
            PVC[(PVC<br>vuls-results)]
        end
    end

    SE1 -->|2. POST /vuls<br>package payload| VS
    SE2 -->|2. POST /vuls<br>package payload| VS
    SE3 -->|2. POST /vuls<br>package payload| VS

    VS -->|3. query CVEs +<br>CVSS scores| VDB
    VS -->|4. write scan results| PVC

    VE -->|5. read result JSON files| PVC
    VE -->|6. POST /reports/:name| API

    USER((User)) -->|7. GET /reports/:name| API

    style API fill:#4a9eff,color:#fff
    style VE fill:#ff9f43,color:#fff
    style VS fill:#ee5a24,color:#fff
    style VDB fill:#636e72,color:#fff
    style SE1 fill:#10ac84,color:#fff
    style SE2 fill:#10ac84,color:#fff
    style SE3 fill:#10ac84,color:#fff
    style USER fill:#8854d0,color:#fff
    style PVC fill:#636e72,color:#fff
```

## Flow

1. **Security Exporter** runs `dpkg-query` or `rpm -qa` on the local server to collect installed packages, versions, and source packages
2. **Security Exporter** sends the package list as a JSON payload to Vuls Server via `POST /vuls`
3. **Vuls Server** queries the **vuls2 nightly database** to match packages against CVEs with CVSS2/CVSS3 scores
4. **Vuls Server** writes the scan result as a JSON file to the shared PVC (`-to-localfile`)
5. **Vuls Exporter** polls the PVC for new result files
6. **Vuls Exporter** pushes each result to the **API** via `POST /reports/:name`
7. **User** queries the API to view reports — `GET /reports` to list, `GET /reports/:name` for details

## Components

| Component | Type | Description |
|---|---|---|
| Security Exporter | Go binary on each server | Collects packages (dpkg/rpm), sends to Vuls Server |
| Vuls Server | k8s Deployment | Scans packages against vuls2 nightly db |
| vuls2 nightly db | SQLite on PVC | Pre-built database with all CVE/advisory/detection data |
| Vuls Exporter | k8s Deployment (same ns) | Watches result files, pushes to API |
| API | k8s Deployment | Stores and serves vulnerability reports |
| PVC | PersistentVolumeClaim | Shared storage for database and scan result files |
