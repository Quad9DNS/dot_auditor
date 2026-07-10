#!/usr/bin/env python3
"""
DoT Auditor report renderer.

Reads a JSON audit produced by dot_auditor.py and renders it as verbose text,
a Markdown table, or an interactive HTML page. Presentation only: this program
performs no network or certificate work and depends on the standard library.

SPDX-License-Identifier: BSD-2-Clause
"""

import argparse
import html
import json
import sys

# The envelope layout this renderer understands. Bump in lockstep with the
# collector when the shape of a record or the envelope changes incompatibly.
SCHEMA_VERSION = 2


def _md_cell(text: object) -> str:
    """Neutralize Markdown table delimiters so cert-supplied text cannot break rows."""
    return str(text).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _h(text: object) -> str:
    """HTML-escape cert-supplied text, including quotes, for safe interpolation."""
    return html.escape(str(text), quote=True)


# Status labels are defined once and shared by every formatter, so the Markdown
# and HTML reports can never drift apart. Each pair maps (True, False) to a
# (label, pill-kind); a None value renders as a dash. Labels are chosen so no
# label in a column is a substring of another, keeping column filters unambiguous.
_DASH = ("-", "none")
_IP_IN_CERT = (("YES", "muted"), ("NO", "muted"))
_EXPIRED = (("EXPIRED", "bad"), ("VALID", "ok"))
_SELF_SIGNED = (("SELF-SIGNED", "bad"), ("CA-ISSUED", "ok"))


def _tls_status(r: dict) -> tuple[str, str]:
    """TLS column label and pill-kind, folding the leaf-certificate result in."""
    if not r["tls_ok"]:
        return ("FAIL", "bad")
    if not r["leaf_cert_received"]:
        return ("NO CERT", "warn")
    return ("OK", "ok")


def _chain_status(r: dict) -> tuple[str, str, str | None]:
    """Chain-trust label, pill-kind, and any retained error.

    Distinguishes an untrusted chain (UNVERIFIED) from a trust check that could
    not complete (UNKNOWN, keeping the error for a tooltip).
    """
    trusted = r.get("issued_by_trusted_ca")
    if trusted is True:
        return ("TRUSTED", "ok", None)
    if trusted is False:
        return ("UNVERIFIED", "bad", None)
    err = r.get("trust_error")
    if err:
        return ("UNKNOWN", "warn", err)
    return (*_DASH, None)


def _bool_status(value: object, states: tuple) -> tuple[str, str]:
    """Pick (label, pill-kind) for a True/False/None value; None renders as a dash."""
    if value is None:
        return _DASH
    return states[0] if value else states[1]


def _pill_td(label: str, kind: str, title: str | None = None) -> str:
    """A table cell holding a status pill. The label is a fixed word, so only the
    optional title (a retained error message) needs escaping.
    """
    attr = f' title="{_h(title)}"' if title else ""
    return f'<td><span class="pill {kind}"{attr}>{label}</span></td>'


def _list_cell(items: list, limit: int = 4) -> str:
    """Monospace cell for a list, collapsing the overflow behind a click-to-expand toggle.

    The hidden names stay in the DOM, so DataTables filtering still matches them.
    """
    if not items:
        return "<td>-</td>"
    shown = ", ".join(_h(x) for x in items[:limit])
    if len(items) <= limit:
        return f'<td class="monospace">{shown}</td>'
    rest = ", ".join(_h(x) for x in items[limit:])
    more = len(items) - limit
    return (
        f'<td class="monospace">{shown} '
        f'<details class="more"><summary>+{more} more</summary>{rest}</details></td>'
    )


def format_verbose(results: list[dict]) -> str:
    """Format results as human-readable verbose output."""
    output = []
    for r in results:
        output.append(f"=== {r['ip']} ({r['domain']}) :{r['port']} ===")
        output.append(
            f" Matching NS hostname(s): {', '.join(r['matching_ns']) or 'none'}"
        )
        output.append(f" SNI used: {r['sni_used'] or 'None'}")
        tls_status = "OK" if r["tls_ok"] else f"FAIL ({r['error_tls']})"
        output.append(f" TLS: {tls_status}")
        output.append(
            f" Leaf certificate received: {'yes' if r['leaf_cert_received'] else 'no'}"
        )

        for key, label in [
            ("cn_list", "CN(s)"),
            ("san_dns", "SAN DNS"),
            ("san_ips", "SAN IPs"),
        ]:
            if r[key]:
                output.append(f" {label}:")
                output.extend(f"   - {item}" for item in r[key])

        if r["not_before"] or r["not_after"]:
            output.append(
                f" Validity: {r['not_before'] or '-'} -> {r['not_after'] or '-'} (expired: {r['is_expired']})"
            )

        if r["issuer_cn"]:
            output.append(f" Issued by: {r['issuer_cn']}")
        if r["is_self_signed"] is not None:
            output.append(f" Self-signed: {r['is_self_signed']}")
        if r["issued_by_trusted_ca"] is not None:
            output.append(f" Chains to system CA: {r['issued_by_trusted_ca']}")
        elif r.get("trust_error"):
            output.append(f" Chains to system CA: unknown ({r['trust_error']})")
        if r["connected_ip_in_cert"] is not None:
            output.append(
                f" Connected IP listed in cert IP SANs: {r['connected_ip_in_cert']}"
            )
        output.append("")

    return "\n".join(output)


def _md_list(items: list) -> str:
    """Render a list of cert-supplied values as a Markdown cell, or a dash if empty."""
    return ", ".join(f"`{_md_cell(x)}`" for x in items) if items else "-"


def format_markdown(results: list[dict]) -> str:
    """Format results as a Markdown table.

    Uses the same columns and the same status words as the HTML report (no
    emoji), so the two views read consistently. The one difference is that
    Markdown cannot collapse long lists interactively, so the SAN columns are
    shown in full.
    """
    headers = [
        "IP",
        "Domain",
        "SNI Used",
        "Matching NS",
        "TLS",
        "Chain Trusted",
        "IP in Cert",
        "Expired",
        "Self-Signed",
        "Issued By",
        "CN(s)",
        "SAN DNS",
        "SAN IPs",
    ]

    output = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join(["---"] * len(headers)) + "|",
    ]

    for r in results:
        row = [
            f"`{_md_cell(r['ip'])}`",
            f"`{_md_cell(r['domain'])}`",
            f"`{_md_cell(r['sni_used'])}`" if r["sni_used"] else "-",
            _md_list(r["matching_ns"]),
            _tls_status(r)[0],
            _chain_status(r)[0],
            _bool_status(r["connected_ip_in_cert"], _IP_IN_CERT)[0],
            _bool_status(r["is_expired"], _EXPIRED)[0],
            _bool_status(r["is_self_signed"], _SELF_SIGNED)[0],
            f"`{_md_cell(r['issuer_cn'])}`" if r["issuer_cn"] else "-",
            _md_list(r["cn_list"]),
            _md_list(r["san_dns"]),
            _md_list(r["san_ips"]),
        ]
        output.append("| " + " | ".join(row) + " |")

    return "\n".join(output)


def format_html(
    results: list[dict], title: str = "DoT Audit Report", provenance: str = ""
) -> str:
    """Format results as HTML table with DataTables for sorting and filtering."""
    css = """
    body { margin: 0; padding: 10px; font-family: Arial, sans-serif; }
    td.monospace { font-family: Consolas, monospace; font-size: 12px; }
    table.dataTable { font-size: 13px; color: #333; }
    table.dataTable thead th { background-color: #f5f5f5; font-weight: 600; cursor: help; position: sticky; top: 0; z-index: 2; }
    table.dataTable tbody td { vertical-align: middle; padding: 3px 8px; }
    table.dataTable tfoot th { background-color: #e8e8e8; padding: 6px 8px; }
    table.dataTable tfoot input { padding: 3px 5px; font-size: 12px; border: 1px solid #ccc; border-radius: 3px; }
    table.dataTable tfoot input:focus { outline: none; border-color: #4a90e2; box-shadow: 0 0 3px rgba(74, 144, 226, 0.5); }
    .tooltip-hint { font-size: 13px; color: #666; margin-top: 5px; font-style: italic; }
    .provenance { font-size: 13px; color: #666; margin: 4px 0 0; }
    .pill { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 11px; font-weight: 700; letter-spacing: 0.02em; white-space: nowrap; }
    .pill.ok { background: #e4f5e8; color: #1a7f37; }
    .pill.bad { background: #fce4e4; color: #b42318; }
    .pill.warn { background: #fdf0d5; color: #9a6700; }
    .pill.muted { background: #eceff2; color: #4a5568; }
    .pill.none { background: transparent; color: #aaa; font-weight: 400; }
    details.more { display: inline; }
    details.more > summary { display: inline; cursor: pointer; color: #4a90e2; font-size: 11px; list-style: none; }
    details.more > summary::-webkit-details-marker { display: none; }
    details.more[open] > summary { color: #888; }
    """

    # Headers with tooltips (header_text, tooltip_description). The "Leaf Cert"
    # column is folded into "TLS" (which shows a distinct "NO CERT" state) since
    # a successful handshake almost always yields a leaf certificate.
    headers_with_tooltips = [
        ("IP", "IP address being audited"),
        ("Domain", "Domain name associated with the IP"),
        ("SNI Used", "Server Name Indication used in TLS handshake"),
        ("Matching NS", "NS hostnames that resolve to this IP"),
        ("TLS", "TLS handshake result (OK, NO CERT if no leaf returned, or FAIL)"),
        ("Chain Trusted", "Certificate chain validates against system CA store"),
        ("IP in Cert", "Connected IP address is listed in certificate's SAN IPs"),
        ("Expired", "Certificate validity relative to now"),
        ("Self-Signed", "Whether the leaf certificate is self-signed"),
        ("Issued By", "Certificate issuer (CA organization and CN)"),
        ("CN(s)", "Common Name(s) from certificate subject"),
        ("SAN DNS", "DNS names from Subject Alternative Name extension"),
        ("SAN IPs", "IP addresses from Subject Alternative Name extension"),
    ]

    headers = [h[0] for h in headers_with_tooltips]

    output = [
        "<!DOCTYPE html>",
        '<html xmlns="http://www.w3.org/1999/xhtml" lang="" xml:lang="">',
        "<head>",
        '  <meta charset="utf-8" />',
        '  <meta name="generator" content="DoT Auditor" />',
        '  <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes" />',
        f"  <title>{_h(title)}</title>",
        '  <link rel="stylesheet" href="https://cdn.datatables.net/2.3.8/css/dataTables.dataTables.min.css" />',
        f"  <style>{css}</style>",
        "</head>",
        "<body>",
        f"<h1>{_h(title)}</h1>",
    ]
    if provenance:
        output.append(f'<p class="provenance">{_h(provenance)}</p>')
    output.extend(
        [
            '<p class="tooltip-hint">Hover over column headers for descriptions</p>',
            '<table id="auditTable" class="display" style="width:100%;">',
            "<thead><tr>" + "".join(f'<th title="{desc}">{name}</th>' for name, desc in headers_with_tooltips) + "</tr></thead>",
            "<tfoot><tr>"
            + "".join(
                f'<th><input type="text" placeholder="Filter {h}" style="width:100%; box-sizing:border-box;" /></th>'
                for h in headers
            )
            + "</tr></tfoot>",
            "<tbody>",
        ]
    )

    for r in results:
        chain_label, chain_kind, chain_err = _chain_status(r)
        cells = [
            f'<td class="monospace">{_h(r["ip"])}</td>',
            f'<td class="monospace">{_h(r["domain"])}</td>',
            (
                f'<td class="monospace">{_h(r["sni_used"])}</td>'
                if r["sni_used"]
                else "<td>-</td>"
            ),
            _list_cell(r["matching_ns"]),
            _pill_td(*_tls_status(r)),
            # "UNVERIFIED"/"UNKNOWN" rather than "UNTRUSTED": DataTables column
            # filters match substrings, so filtering "trusted" must not also
            # catch the negatives. The labels share no substring.
            _pill_td(chain_label, chain_kind, chain_err),
            _pill_td(*_bool_status(r["connected_ip_in_cert"], _IP_IN_CERT)),
            _pill_td(*_bool_status(r["is_expired"], _EXPIRED)),
            _pill_td(*_bool_status(r["is_self_signed"], _SELF_SIGNED)),
            (
                f'<td class="monospace">{_h(r["issuer_cn"])}</td>'
                if r["issuer_cn"]
                else "<td>-</td>"
            ),
            _list_cell(r["cn_list"]),
            _list_cell(r["san_dns"]),
            _list_cell(r["san_ips"]),
        ]
        output.append("<tr>" + "".join(cells) + "</tr>")

    footer = (
        f'Generated with <a href="https://github.com/Quad9DNS/dot_auditor">DoT Auditor</a>'
        f". {_h(provenance)}"
        if provenance
        else 'Generated with <a href="https://github.com/Quad9DNS/dot_auditor">DoT Auditor</a>'
    )
    output.extend(
        [
            "</tbody>",
            "</table>",
            '<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>',
            '<script src="https://cdn.datatables.net/2.3.8/js/dataTables.min.js"></script>',
            "<script>",
            "$(document).ready(function() {",
            '  var table = $("#auditTable").DataTable({',
            '    "pageLength": -1,',
            '    "lengthMenu": [[50, 100, 200, -1], [50, 100, 200, "All"]],',
            '    "order": [],',
            '    "columnDefs": [{ "orderable": true, "targets": "_all" }],',
            '    "dom": "lfrtip<\\"bottom-info\\">",',
            '    "language": {',
            '      "search": "Filter records:",',
            '      "lengthMenu": "Show _MENU_ entries per page",',
            '      "info": "Showing _START_ to _END_ of _TOTAL_ servers"',
            "    },",
            '    "drawCallback": function() {',
            f'      $(".bottom-info").html(\'<div style="text-align: center; margin-top: 20px; color: #666;">{footer}</div>\');',
            "    },",
            '    "initComplete": function() {',
            "      this.api().columns().every(function() {",
            "        var column = this;",
            "        $('input', this.footer()).on('keyup change clear', function() {",
            "          if (column.search() !== this.value) {",
            "            column.search(this.value).draw();",
            "          }",
            "        });",
            "      });",
            "    }",
            "  });",
            "});",
            "</script>",
            "</body>",
            "</html>",
        ]
    )

    return "\n".join(output)


def load_envelope(path: str) -> dict:
    """Read and validate a collector JSON envelope from a path, or '-' for stdin."""
    try:
        if path == "-":
            envelope = json.load(sys.stdin)
        else:
            with open(path, "r", encoding="utf-8") as f:
                envelope = json.load(f)
    except FileNotFoundError:
        sys.exit(f"Error: File '{path}' not found")
    except PermissionError:
        sys.exit(f"Error: Permission denied reading '{path}'")
    except json.JSONDecodeError as e:
        sys.exit(f"Error: '{path}' is not valid JSON: {e}")

    if not isinstance(envelope, dict) or "results" not in envelope:
        sys.exit(
            "Error: input is not a DoT Auditor envelope "
            "(expected an object with a 'results' key). "
            "Produce one with: dot_auditor.py <csv> -o audit.json"
        )

    version = envelope.get("schema_version")
    if version != SCHEMA_VERSION:
        sys.exit(
            f"Error: unsupported schema_version {version!r}; "
            f"this renderer understands version {SCHEMA_VERSION}. "
            "Use a matching dot_auditor/dot_report pair."
        )

    return envelope


def provenance_line(envelope: dict) -> str:
    """One-line summary of where the data came from, for report headers."""
    source = envelope.get("source") or "unknown source"
    generated = envelope.get("generated_at") or "unknown time"
    params = envelope.get("params") or {}
    port = params.get("port")
    count = len(envelope.get("results", []))
    port_note = f", port {port}" if port is not None else ""
    return f"Source: {source}{port_note}. {count} servers. Collected {generated}."


def main() -> None:
    """Render a DoT Auditor JSON audit into a report."""
    ap = argparse.ArgumentParser(
        description="Render a DoT Auditor JSON audit as verbose text, Markdown, or HTML."
    )
    ap.add_argument(
        "input",
        nargs="?",
        default="-",
        help="Path to the collector's JSON output, or '-' for stdin (default: stdin).",
    )
    ap.add_argument(
        "--format",
        dest="output_format",
        choices=["verbose", "markdown", "html"],
        default="html",
        help="Report format (default: html)",
    )
    ap.add_argument(
        "-o", "--output", dest="output_file", help="Output file path (default: stdout)"
    )
    args = ap.parse_args()

    envelope = load_envelope(args.input)
    results = envelope["results"]
    source = envelope.get("source") or "audit"
    provenance = provenance_line(envelope)

    formatters = {
        "html": lambda: format_html(
            results, title=f"DoT Audit Report: {source}", provenance=provenance
        ),
        "markdown": lambda: format_markdown(results),
        "verbose": lambda: format_verbose(results),
    }
    output = formatters[args.output_format]()

    if args.output_file:
        try:
            with open(args.output_file, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"Output written to {args.output_file}", file=sys.stderr)
        except OSError as e:
            sys.exit(f"Error writing to file {args.output_file}: {e}")
    else:
        print(output)


if __name__ == "__main__":
    main()
