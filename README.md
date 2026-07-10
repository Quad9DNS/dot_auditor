# DoT Auditor

[![CI](https://github.com/Quad9DNS/dot_auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/Quad9DNS/dot_auditor/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Quad9DNS/dot_auditor/branch/main/graph/badge.svg)](https://codecov.io/gh/Quad9DNS/dot_auditor)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

A tool for auditing TLS certificates on DNS-over-TLS servers.

## Overview

Analyzes TLS certificates on DoT servers (port 853). Resolves NS records for each domain, uses them as SNI during TLS handshake, and extracts certificate information.

The work is split across two programs. `dot_auditor.py` collects the data and writes a JSON audit; `dot_report.py` turns that JSON into a human-readable report. Collection and presentation are decoupled, so a single audit can be re-rendered in any format, kept as a machine-readable record, or diffed over time without re-probing the servers. The renderer depends only on the Python standard library.

## Features

- Automatic SNI selection from NS records
- Certificate analysis (CN, SAN, validity, chain trust, issuer)
- IP address validation (checks if connected IP is listed in certificate SAN IPs)
- JSON audit as the stored format, with a separate renderer for verbose, Markdown, and HTML reports
- Self-signed and expired certificate detection with visual highlighting
- Interactive HTML reports with DataTables (sorting, filtering, search)
- Per-column filtering in HTML output
- Concurrent processing with configurable workers
- Detailed certificate validation and chain trust verification

## Installation

Requires Python 3.10 or later.

```bash
pip install dnspython cryptography
```

## Usage

### Basic Usage

Collect an audit into JSON, then render it:

```bash
python3 dot_auditor.py input.csv -o audit.json
python3 dot_report.py audit.json --format html -o report.html
```

The two programs also pipe together when you do not need to keep the JSON:

```bash
python3 dot_auditor.py input.csv | python3 dot_report.py --format markdown
```

### Input Format

The CSV file should contain at least two columns: IP address and domain name.

Example `input.csv`:
```csv
45.55.10.200,powerdns.com
206.189.140.177,technitium.com
2604:a880:1:20::132:5001,powerdns.com
```

### Collector Options (`dot_auditor.py`)

| Option | Description |
|--------|-------------|
| `csv_file` | CSV file with IP and domain columns (required) |
| `--has-header` | Skip the first CSV row as header |
| `--delimiter` | CSV delimiter (default: `,`) |
| `--ip-col` | Zero-based index of the IP column (default: `0`) |
| `--domain-col` | Zero-based index of the domain column (default: `1`) |
| `--port` | Port to check (default: `853`) |
| `--timeout` | Timeout for DNS and TLS operations in seconds (default: `5.0`) |
| `--workers` | Number of concurrent checks (default: `64`) |
| `-o`, `--output` | Path to write the JSON audit (default: stdout) |

### Renderer Options (`dot_report.py`)

| Option | Description |
|--------|-------------|
| `input` | Path to the collector's JSON, or `-` for stdin (default: stdin) |
| `--format` | Report format: `verbose`, `markdown`, or `html` (default: `html`) |
| `-o`, `--output` | Output file path (default: stdout) |

### The JSON Audit

The collector emits a self-describing envelope: provenance about the run followed by one record per audited server under `results`.

```json
{
  "schema_version": 1,
  "generated_at": "2026-07-10T12:00:00+00:00",
  "tool": "dot_auditor",
  "tool_version": "1.0.0",
  "source": "input",
  "params": { "port": 853, "timeout": 5.0 },
  "results": [
    {
      "ip": "45.55.10.200",
      "domain": "powerdns.com",
      "port": 853,
      "matching_ns": ["pdns-public-ns2.powerdns.com"],
      "sni_used": "pdns-public-ns2.powerdns.com",
      "tls_ok": true,
      "error_tls": null,
      "leaf_cert_received": true,
      "connected_ip": "45.55.10.200",
      "not_before": "2025-01-15T12:00:00+00:00",
      "not_after": "2026-01-15T12:00:00+00:00",
      "is_expired": false,
      "is_self_signed": false,
      "issued_by_trusted_ca": true,
      "issuer_cn": "Let's Encrypt (R12)",
      "cn_list": ["*.powerdns.com"],
      "san_dns": ["*.powerdns.com", "powerdns.com"],
      "san_ips": [],
      "connected_ip_in_cert": false
    }
  ]
}
```

### Report Formats

Pass one of these to `dot_report.py --format`.

#### Verbose

Detailed human-readable output with all certificate information:

```bash
python3 dot_report.py audit.json --format verbose
```

```
=== 45.55.10.200 (powerdns.com) :853 ===
 Matching NS hostname(s): pdns-public-ns2.powerdns.com
 SNI used: pdns-public-ns2.powerdns.com
 TLS: OK
 Leaf certificate received: yes
 CN(s):
   - *.powerdns.com
 SAN DNS:
   - *.powerdns.com
   - powerdns.com
 Validity: 2025-01-15T12:00:00+00:00 -> 2026-01-15T12:00:00+00:00 (expired: False)
 Issued by: Let's Encrypt (R12)
 Self-signed: False
 Chains to system CA: True
 Connected IP listed in cert IP SANs: False
```

#### Markdown

Formatted as a table for documentation and reports:

```bash
python3 dot_report.py audit.json --format markdown
```

| IP | Domain | SNI Used | Matching NS | TLS | Leaf Cert | Chain Trusted | IP in Cert | Expired | Self-Signed | Issued By | CN(s) | SAN DNS | SAN IPs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `45.55.10.200` | `powerdns.com` | `pdns-public-ns2.powerdns.com` | `pdns-public-ns2.powerdns.com` | ✅ | ✅ | ✅ | YES | NO | NO | `Let's Encrypt (R12)` | `*.powerdns.com` | `*.powerdns.com`, `powerdns.com` | - |

#### HTML

Interactive HTML reports with DataTables integration for advanced filtering and sorting:

```bash
python3 dot_report.py audit.json --format html -o report.html
```

Features:
- **Sortable columns**: Click any column header to sort
- **Global search**: Filter across all columns at once
- **Per-column filtering**: Individual search boxes for each column
- **Pagination**: Navigate through large datasets (50 entries per page)
- **Visual highlighting**: Expired and self-signed certificates shown in red
- **Column tooltips**: Hover over column headers for descriptions
- **Provenance**: source file and collection time shown in the report header and footer
- **Responsive design**: Works on desktop and mobile browsers

The HTML output uses monospace fonts for technical data (IPs, domains, hostnames) and includes all certificate details in a clean, professional format.

Interactive features powered by [DataTables](https://datatables.net/) - a powerful jQuery plugin for enhanced HTML tables.

**Sample Reports**: View live examples of HTML and Markdown output:
- [HTML Report (20260311.html)](https://quad9dns.github.io/dot_auditor/output/20260311.html)
- [Markdown Report (20260311.md)](https://quad9dns.github.io/dot_auditor/output/20260311.md)

## How It Works

1. Query NS records for the domain
2. Resolve NS hostnames to find which matches the target IP
3. Use matching NS hostname as SNI during TLS handshake
4. Retrieve certificate and validate against system CA store
5. Extract certificate details (CN, SAN, validity, chain trust)

## Use Cases

- Audit DoT server certificate configurations
- Monitor certificate expiration
- Verify certificate chain trust
- Check for self-signed certificates

## Examples

### Audit a list of public DNS servers and produce a Markdown report

```bash
python3 dot_auditor.py public-dns-servers.csv -o audit.json
python3 dot_report.py audit.json --format markdown -o audit-report.md
```

### Check with custom timeout and port

```bash
python3 dot_auditor.py servers.csv --port=8853 --timeout=10.0 --workers=32 -o audit.json
```

### Keep the JSON audit for further processing

```bash
python3 dot_auditor.py servers.csv -o results.json
```

The `results.json` file is the audit of record; render it whenever needed without re-probing the servers.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and contribution guidelines.

## Dependencies

This project relies on the following excellent open-source libraries:

- **[dnspython](https://www.dnspython.org/)** - DNS toolkit for Python
- **[cryptography](https://cryptography.io/)** - Cryptographic recipes and primitives
- **[DataTables](https://datatables.net/)** - jQuery plugin for interactive HTML tables (used in HTML output)

## License

This project is licensed under the BSD 2-Clause License - see the [LICENSE](LICENSE) file for details.
