"""
Unit tests for the DoT Auditor report renderer.

SPDX-License-Identifier: BSD-2-Clause
"""

import json
import re

import pytest
from unittest.mock import patch

import dot_report


def _result(**overrides):
    """A complete result record; override individual fields per test."""
    base = {
        "ip": "192.168.1.1",
        "domain": "example.com",
        "port": 853,
        "matching_ns": ["ns1.example.com"],
        "sni_used": "ns1.example.com",
        "tls_ok": True,
        "error_tls": None,
        "leaf_cert_received": True,
        "connected_ip": "192.168.1.1",
        "cn_list": ["example.com"],
        "san_dns": ["www.example.com"],
        "san_ips": ["192.168.1.100"],
        "not_before": "2025-01-01T00:00:00+00:00",
        "not_after": "2026-01-01T00:00:00+00:00",
        "is_expired": False,
        "is_self_signed": False,
        "issued_by_trusted_ca": True,
        "issuer_cn": "Let's Encrypt Authority X3",
        "connected_ip_in_cert": False,
    }
    base.update(overrides)
    return base


def _envelope(results):
    """Wrap results in a current-schema envelope."""
    return {
        "schema_version": dot_report.SCHEMA_VERSION,
        "generated_at": "2026-07-10T00:00:00+00:00",
        "tool": "dot_auditor",
        "tool_version": "1.0.0",
        "source": "sample",
        "params": {"port": 853, "timeout": 5.0},
        "results": results,
    }


class TestFormatters:
    """Test output formatter functions."""

    def test_format_verbose(self):
        """Test verbose formatter."""
        output = dot_report.format_verbose([_result()])

        assert "192.168.1.1" in output
        assert "example.com" in output
        assert "ns1.example.com" in output
        assert "www.example.com" in output
        assert "192.168.1.100" in output
        assert "Let's Encrypt Authority X3" in output
        assert "TLS: OK" in output

    def test_format_markdown(self):
        """Test markdown formatter with backticks for IPs and hostnames."""
        output = dot_report.format_markdown([
            _result(cn_list=["*.example.com"],
                    san_dns=["*.example.com", "example.com"])
        ])

        assert "|" in output
        assert "IP" in output
        assert "Domain" in output
        assert "Issued By" in output
        assert "`192.168.1.1`" in output
        assert "`example.com`" in output
        assert "`ns1.example.com`" in output
        assert "`*.example.com`" in output
        assert "`192.168.1.100`" in output
        assert "`Let's Encrypt Authority X3`" in output
        assert "✅" in output  # Successful TLS

    def test_format_html_includes_provenance(self):
        """The HTML report surfaces where the data came from."""
        output = dot_report.format_html(
            [_result()], title="DoT Audit Report: sample",
            provenance="Source: sample, port 853. 1 servers. Collected now.",
        )
        assert "DoT Audit Report: sample" in output
        assert "Source: sample" in output
        assert "192.168.1.1" in output


class TestHtmlDensity:
    """The HTML view drops redundant width and encodes status as filterable pills."""

    def test_leaf_cert_column_is_dropped(self):
        """Leaf Cert is folded into TLS, so it is no longer its own column."""
        out = dot_report.format_html([_result()])
        assert "<th title=" in out
        assert ">Leaf Cert<" not in out
        assert ">TLS<" in out

    def test_tls_shows_no_cert_state(self):
        """A handshake with no leaf certificate reads NO CERT, not a bare OK/FAIL."""
        out = dot_report.format_html(
            [_result(tls_ok=True, leaf_cert_received=False)]
        )
        assert "NO CERT" in out

    def test_status_cells_are_pills_not_emoji(self):
        """Status is text in CSS pills, which DataTables can filter and sort."""
        out = dot_report.format_html([_result()])
        assert 'class="pill ok"' in out
        assert "✅" not in out and "❌" not in out
        # A severity word carries meaning without relying on color.
        assert "TRUSTED" in out

    def test_long_san_list_is_collapsed(self):
        """A large SAN DNS set is truncated with an expand toggle, keeping all names."""
        names = [f"ns{i}.example.com" for i in range(12)]
        out = dot_report.format_html([_result(san_dns=names)])
        assert "+8 more" in out  # first 4 shown, remaining behind a toggle
        assert "<details" in out
        assert "ns11.example.com" in out  # hidden name still present for filtering

    def test_uses_datatables_2_3(self):
        """The report pulls the pinned DataTables release."""
        out = dot_report.format_html([_result()])
        assert "datatables.net/2.3.8/" in out
        assert "jquery-3.7.1" in out


class TestOutputInjection:
    """Certificate fields are attacker-controlled and must not break the output."""

    @staticmethod
    def _hostile_result():
        """A result whose cert-derived fields carry HTML and Markdown metacharacters."""
        return _result(
            ip="192.0.2.1", domain="evil.example", matching_ns=[], sni_used=None,
            issued_by_trusted_ca=False,
            issuer_cn="<script>alert(document.domain)</script>",
            cn_list=['" onmouseover="alert(1)'],
            san_dns=["a.evil | b.evil"], san_ips=[],
        )

    def test_html_escapes_script_and_attribute_payloads(self):
        """No raw script tag or attribute breakout may reach the page."""
        out = dot_report.format_html([self._hostile_result()])
        assert "<script>alert(document.domain)</script>" not in out
        assert '" onmouseover="alert(1)' not in out
        assert "&lt;script&gt;" in out  # payload survives, inert

    def test_markdown_pipe_does_not_add_a_column(self):
        """A pipe in a SAN name must not shift the table's column count."""
        out = dot_report.format_markdown([self._hostile_result()])
        header, row = out.splitlines()[0], out.splitlines()[2]
        # Only unescaped pipes act as column delimiters.
        delimiters = lambda s: len(re.findall(r"(?<!\\)\|", s))
        assert delimiters(row) == delimiters(header)
        assert "\\|" in row  # the SAN pipe was escaped, not dropped


class TestLoadEnvelope:
    """Test envelope reading and schema validation."""

    def test_valid_envelope_round_trips(self, tmp_path):
        """A well-formed envelope loads and exposes its results."""
        path = tmp_path / "audit.json"
        path.write_text(json.dumps(_envelope([_result()])))
        env = dot_report.load_envelope(str(path))
        assert env["results"][0]["ip"] == "192.168.1.1"

    def test_stdin_input(self, monkeypatch):
        """'-' reads the envelope from stdin."""
        import io
        monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_envelope([]))))
        env = dot_report.load_envelope("-")
        assert env["results"] == []

    def test_unsupported_schema_version_exits(self, tmp_path):
        """A newer/older schema is refused with a clear message, not a traceback."""
        path = tmp_path / "future.json"
        env = _envelope([])
        env["schema_version"] = dot_report.SCHEMA_VERSION + 1
        path.write_text(json.dumps(env))
        with pytest.raises(SystemExit) as exc:
            dot_report.load_envelope(str(path))
        assert "schema_version" in str(exc.value)

    def test_not_an_envelope_exits(self, tmp_path):
        """A bare results array (or any non-envelope) is rejected."""
        path = tmp_path / "bare.json"
        path.write_text(json.dumps([_result()]))
        with pytest.raises(SystemExit) as exc:
            dot_report.load_envelope(str(path))
        assert "envelope" in str(exc.value)

    def test_invalid_json_exits(self, tmp_path):
        """Malformed JSON is reported, not raised."""
        path = tmp_path / "broken.json"
        path.write_text("{not json")
        with pytest.raises(SystemExit) as exc:
            dot_report.load_envelope(str(path))
        assert "not valid JSON" in str(exc.value)

    def test_missing_file_exits(self):
        """A nonexistent path exits cleanly."""
        with pytest.raises(SystemExit) as exc:
            dot_report.load_envelope("/nonexistent/audit.json")
        assert "not found" in str(exc.value)


class TestRendererCLI:
    """Test the renderer end to end through main()."""

    def test_main_renders_markdown_from_file(self, tmp_path, capsys):
        """main() reads an envelope file and writes the requested format."""
        path = tmp_path / "audit.json"
        path.write_text(json.dumps(_envelope([_result()])))
        with patch("sys.argv",
                   ["dot_report.py", str(path), "--format", "markdown"]):
            dot_report.main()
        out = capsys.readouterr().out
        assert "`192.168.1.1`" in out
        assert "Issued By" in out
