# APISentry — AI-Powered API Security Scanner

[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-API%20Top%2010-red)](https://owasp.org/API-Security/)

**Find OWASP API Top 10 vulnerabilities in your CI/CD pipeline. $49/mo flat.**

APISentry scans your API for BOLA, broken auth, mass assignment, rate limiting issues, and function-level auth vulnerabilities — automatically, on every PR.

```bash
apisentry scan --spec openapi.yaml --target https://api.yourapp.com
```

```
✓ Parsed 47 endpoints
✓ Generated 891 attack tests

[1] CRITICAL — Broken Auth (API2:2023)
    GET /api/orders/42 → HTTP 200 without token

[2] HIGH — BOLA (API1:2023)
    GET /api/users/1337 → HTTP 200 (unauthorized object)

[3] HIGH — Data Exposure (API3:2023)
    card_number found in response body

TOTAL: 1 CRITICAL · 2 HIGH · 8 MEDIUM
```

## Features

- **OWASP API Top 10** — Full coverage of all 10 categories: BOLA, broken auth, mass assignment, rate limiting, function-level auth, injection, SSRF, misconfig, inventory management
- **CI/CD native** — GitHub Actions integration with SARIF upload and PR comments
- **AI false-positive filtering** — Claude Haiku 4.5 classifies findings, reduces noise
- **Multiple output formats** — text, JSON, HTML report, SARIF 2.1.0
- **Zero infrastructure** — single Go binary, no agents, no sidecars
- **OpenAPI 2.0 + 3.x** — Supports Swagger 2.0, OpenAPI 3.0, and 3.1

## Quick Start

### Install

```bash
# macOS (Apple Silicon)
curl -L https://github.com/apisentry-dev/apisentry/releases/latest/download/apisentry-darwin-arm64 -o apisentry
chmod +x apisentry && sudo mv apisentry /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/apisentry-dev/apisentry/releases/latest/download/apisentry-darwin-amd64 -o apisentry
chmod +x apisentry && sudo mv apisentry /usr/local/bin/

# Linux
curl -L https://github.com/apisentry-dev/apisentry/releases/latest/download/apisentry-linux-amd64 -o apisentry
chmod +x apisentry && sudo mv apisentry /usr/local/bin/

# Windows — download apisentry-windows-amd64.exe from:
# https://github.com/apisentry-dev/apisentry/releases/latest
```

### Run a scan

```bash
# Basic scan
apisentry scan --spec openapi.yaml --target https://api.yourapp.com

# With auth token
apisentry scan --spec openapi.yaml --target https://api.yourapp.com --token YOUR_JWT

# HTML report
apisentry scan --spec openapi.yaml --target https://api.yourapp.com \
  --format html --output report.html

# SARIF for GitHub Code Scanning
apisentry scan --spec openapi.yaml --target https://api.yourapp.com \
  --format sarif --output results.sarif

# With AI false-positive filtering (requires ANTHROPIC_API_KEY)
ANTHROPIC_API_KEY=sk-ant-... apisentry scan --spec openapi.yaml \
  --target https://api.yourapp.com --ai
```

### GitHub Actions (2-minute setup)

```yaml
# .github/workflows/api-security.yml
name: API Security Scan
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: apisentry/apisentry-action@v1
        with:
          spec-path: openapi.yaml
          base-url: https://api.yourapp.com
          token: ${{ secrets.API_TOKEN }}
          severity-threshold: high
```

Results appear in GitHub Code Scanning. PRs get commented with a findings summary. Merge is blocked if critical/high findings are detected.

## CLI Reference

```
apisentry scan [flags]

Flags:
  -s, --spec string         Path to OpenAPI spec file (required)
  -t, --target string       Target API base URL (required)
      --token string        Bearer token for authenticated requests
  -f, --format string       Output format: text|json|html|sarif (default "text")
  -o, --output string       Write report to file
      --ai                  Enable AI false-positive filtering
      --concurrency int     Parallel HTTP workers (default 5)
      --dry-run             Generate attack plan without sending requests
```

## Architecture

```
openapi.yaml
     │
     ▼
┌─────────────┐     ┌──────────────────────────────────────────┐
│   Parser    │────▶│              Orchestrator                 │
│ (kin-openapi│     │  BOLA · BrokenAuth · Property ·          │
│   3.0/3.1)  │     │  RateLimit · FuncAuth · Injection ·      │
│             │     │  SSRF · Misconfig · Inventory            │
└─────────────┘     └──────────────────┬───────────────────────┘
                                       │ 891 AttackCases
                                       ▼
                    ┌──────────────────────────────────────────┐
                    │            HTTP Executor                  │
                    │  rate-limited · concurrent · retry        │
                    └──────────────────┬───────────────────────┘
                                       │ Findings
                                       ▼
                    ┌──────────────────────────────────────────┐
                    │           AI Analyzer (optional)          │
                    │  Claude Haiku 4.5 · false-positive filter │
                    └──────────────────┬───────────────────────┘
                                       │
                                       ▼
                    ┌──────────────────────────────────────────┐
                    │              Report                       │
                    │  text · JSON · HTML · SARIF 2.1.0        │
                    └──────────────────────────────────────────┘
```

## Vulnerability Coverage

| OWASP ID | Vulnerability | Status |
|----------|--------------|--------|
| API1:2023 | BOLA (Broken Object Level Authorization) | ✅ |
| API2:2023 | Broken Authentication | ✅ |
| API3:2023 | Broken Object Property Level Authorization | ✅ |
| API4:2023 | Unrestricted Resource Consumption | ✅ |
| API5:2023 | Broken Function Level Authorization | ✅ |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | ✅ |
| API7:2023 | Server Side Request Forgery | ✅ |
| API8:2023 | Security Misconfiguration | ✅ |
| API9:2023 | Improper Inventory Management | ✅ |
| API10:2023 | Unsafe Consumption of APIs | ✅ |

## Build from Source

```bash
git clone https://github.com/apisentry-dev/apisentry
cd apisentry
go build -o apisentry .

# Cross-compile for all platforms
make build-all

# Docker
make build-docker
docker run --rm apisentry scan --spec /spec.yaml --target https://api.example.com
```

## License

CLI: MIT. SaaS platform: proprietary.

---

**[apisentry-web.vercel.app](https://apisentry-web.vercel.app)** · [Join beta waitlist](https://apisentry-web.vercel.app/#waitlist) · [Twitter](https://twitter.com/apisentry_ai)
