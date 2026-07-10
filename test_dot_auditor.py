"""
Unit tests for DoT Auditor.

SPDX-License-Identifier: BSD-2-Clause
"""

import json
import re

import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
import dot_auditor


class TestUtilities:
    """Test utility functions."""

    def test_is_ip_valid_ipv4(self):
        """Test is_ip with valid IPv4 address."""
        assert dot_auditor.is_ip("192.168.1.1") is True
        assert dot_auditor.is_ip("8.8.8.8") is True

    def test_is_ip_valid_ipv6(self):
        """Test is_ip with valid IPv6 address."""
        assert dot_auditor.is_ip("2001:4860:4860::8888") is True
        assert dot_auditor.is_ip("::1") is True

    def test_is_ip_invalid(self):
        """Test is_ip with invalid IP addresses."""
        assert dot_auditor.is_ip("not-an-ip") is False
        assert dot_auditor.is_ip("999.999.999.999") is False
        assert dot_auditor.is_ip("") is False

    def test_now_utc(self):
        """Test now_utc returns datetime with UTC timezone."""
        result = dot_auditor.now_utc()
        assert isinstance(result, datetime)
        assert result.tzinfo == timezone.utc


class TestCertHelpers:
    """Test certificate helper functions."""

    def test_extract_cns_empty(self):
        """Test extract_cns with empty cert."""
        cert = {}
        assert dot_auditor.extract_cns(cert) == []

    def test_extract_cns_single_cn(self):
        """Test extract_cns with single CommonName."""
        cert = {
            "subject": (
                (("commonName", "example.com"),),
            )
        }
        assert dot_auditor.extract_cns(cert) == ["example.com"]

    def test_extract_cns_multiple_cn(self):
        """Test extract_cns with multiple CommonNames (de-duped)."""
        cert = {
            "subject": (
                (("commonName", "example.com"),),
                (("commonName", "example.com"),),  # duplicate
                (("commonName", "test.com"),),
            )
        }
        result = dot_auditor.extract_cns(cert)
        assert "example.com" in result
        assert "test.com" in result
        assert len(result) == 2  # de-duped

    def test_names_from_cert_with_san(self):
        """Test names_from_cert with SAN entries."""
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "subjectAltName": (
                ("DNS", "www.example.com"),
                ("DNS", "mail.example.com"),
                ("IP Address", "192.168.1.1"),
            )
        }
        cn_list, san_dns, san_ips = dot_auditor.names_from_cert(cert)

        assert "example.com" in cn_list
        assert "example.com" in san_dns  # CN added to DNS list
        assert "www.example.com" in san_dns
        assert "mail.example.com" in san_dns
        assert "192.168.1.1" in san_ips

    def test_names_from_cert_normalizes_ipv6_san(self):
        """SAN IPv6 entries are canonicalized, not kept as the CA wrote them.

        getpeercert() renders IPv6 uppercase and uncompressed, so the raw text
        never matches the compressed lowercase form getpeername() returns.
        """
        cert = {
            "subject": (),
            "subjectAltName": (
                ("IP Address", "2001:19F0:6C00:8501:5400:FF:FE04:3F"),
                ("IP Address", "2001:41D0:305:2100:0:0:0:643A"),
                ("IP Address", "108.61.171.156"),
            )
        }
        _, _, san_ips = dot_auditor.names_from_cert(cert)

        assert "2001:19f0:6c00:8501:5400:ff:fe04:3f" in san_ips
        assert "2001:41d0:305:2100::643a" in san_ips
        assert "108.61.171.156" in san_ips

    def test_parse_times_valid(self):
        """Test parse_times with valid dates."""
        cert = {
            "notBefore": "Jan 1 00:00:00 2025 GMT",
            "notAfter": "Dec 31 23:59:59 2025 GMT"
        }
        nb, na = dot_auditor.parse_times(cert)

        assert isinstance(nb, datetime)
        assert isinstance(na, datetime)
        assert nb.year == 2025
        assert na.year == 2025
        assert nb.tzinfo == timezone.utc

    def test_parse_times_invalid(self):
        """Test parse_times with invalid/missing dates."""
        cert = {
            "notBefore": "invalid date",
            "notAfter": None
        }
        nb, na = dot_auditor.parse_times(cert)

        assert nb is None
        assert na is None

class TestDNSHelpers:
    """Test DNS helper functions."""

    @patch('dot_auditor.dns.resolver.Resolver')
    def test_dns_get_ns_success(self, mock_resolver_class):
        """Test dns_get_ns with successful response."""
        # Clear cache before test
        dot_auditor._dns_ns_cache.clear()

        # Mock the resolver
        mock_resolver = MagicMock()
        mock_resolver_class.return_value = mock_resolver

        # Mock DNS response
        mock_rr = MagicMock()
        mock_rr.target = "ns1.example.com."
        mock_resolver.resolve.return_value = [mock_rr]

        result = dot_auditor.dns_get_ns("example.com")

        assert result == ["ns1.example.com"]
        assert "example.com" in dot_auditor._dns_ns_cache

    @patch('dot_auditor.dns.resolver.Resolver')
    def test_dns_get_ns_cached(self, mock_resolver_class):
        """Test dns_get_ns returns cached result."""
        # Set cache
        dot_auditor._dns_ns_cache["test.com"] = ["cached.ns.com"]

        result = dot_auditor.dns_get_ns("test.com")

        assert result == ["cached.ns.com"]
        # Resolver should not be called for cached result
        mock_resolver_class.assert_not_called()

    @patch('dot_auditor.dns.resolver.Resolver')
    def test_dns_get_addrs_success(self, mock_resolver_class):
        """Test dns_get_addrs with successful A/AAAA responses."""
        # Clear cache before test
        dot_auditor._dns_addr_cache.clear()

        mock_resolver = MagicMock()
        mock_resolver_class.return_value = mock_resolver

        # Mock A record
        mock_a = MagicMock()
        mock_a.__str__ = lambda self: "192.168.1.1"

        # Mock AAAA record
        mock_aaaa = MagicMock()
        mock_aaaa.__str__ = lambda self: "2001:db8::1"

        mock_resolver.resolve.side_effect = [
            [mock_a],  # A record response
            [mock_aaaa]  # AAAA record response
        ]

        result = dot_auditor.dns_get_addrs("example.com")

        assert "192.168.1.1" in result
        assert "2001:db8::1" in result


class TestFormatters:
    """Test output formatter functions."""

    def test_format_verbose(self):
        """Test verbose formatter."""
        results = [{
            "ip": "192.168.1.1",
            "domain": "example.com",
            "port": 853,
            "matching_ns": ["ns1.example.com"],
            "sni_used": "ns1.example.com",
            "tls_ok": True,
            "error_tls": None,
            "leaf_cert_received": True,
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
        }]

        output = dot_auditor.format_verbose(results)

        assert "192.168.1.1" in output
        assert "example.com" in output
        assert "ns1.example.com" in output
        assert "www.example.com" in output
        assert "192.168.1.100" in output
        assert "Let's Encrypt Authority X3" in output
        assert "TLS: OK" in output

    def test_format_markdown(self):
        """Test markdown formatter with backticks for IPs and hostnames."""
        results = [{
            "ip": "192.168.1.1",
            "domain": "example.com",
            "port": 853,
            "matching_ns": ["ns1.example.com"],
            "sni_used": "ns1.example.com",
            "tls_ok": True,
            "error_tls": None,
            "leaf_cert_received": True,
            "cn_list": ["*.example.com"],
            "san_dns": ["*.example.com", "example.com"],
            "san_ips": ["192.168.1.100"],
            "not_before": "2025-01-01T00:00:00+00:00",
            "not_after": "2026-01-01T00:00:00+00:00",
            "is_expired": False,
            "is_self_signed": False,
            "issued_by_trusted_ca": True,
            "issuer_cn": "Let's Encrypt Authority X3",
            "connected_ip_in_cert": False,
        }]

        output = dot_auditor.format_markdown(results)

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

    def test_format_json(self):
        """Test JSON formatter."""
        results = [{
            "ip": "192.168.1.1",
            "domain": "example.com",
            "tls_ok": True,
        }]

        output = dot_auditor.format_json(results)

        assert '"ip": "192.168.1.1"' in output
        assert '"domain": "example.com"' in output
        assert '"tls_ok": true' in output


class TestOutputInjection:
    """Certificate fields are attacker-controlled and must not break the output."""

    @staticmethod
    def _hostile_result():
        """A result whose cert-derived fields carry HTML and Markdown metacharacters."""
        return {
            "ip": "192.0.2.1", "domain": "evil.example", "port": 853,
            "matching_ns": [], "sni_used": None, "tls_ok": True, "error_tls": None,
            "leaf_cert_received": True, "connected_ip": "192.0.2.1",
            "not_before": "2025-01-01T00:00:00+00:00",
            "not_after": "2030-01-01T00:00:00+00:00",
            "is_expired": False, "is_self_signed": False,
            "issued_by_trusted_ca": False,
            "issuer_cn": "<script>alert(document.domain)</script>",
            "cn_list": ['" onmouseover="alert(1)'],
            "san_dns": ["a.evil | b.evil"], "san_ips": [],
            "connected_ip_in_cert": False,
        }

    def test_html_escapes_script_and_attribute_payloads(self):
        """No raw script tag or attribute breakout may reach the page."""
        out = dot_auditor.format_html([self._hostile_result()])
        assert "<script>alert(document.domain)</script>" not in out
        assert '" onmouseover="alert(1)' not in out
        assert "&lt;script&gt;" in out  # payload survives, inert

    def test_markdown_pipe_does_not_add_a_column(self):
        """A pipe in a SAN name must not shift the table's column count."""
        out = dot_auditor.format_markdown([self._hostile_result()])
        header, row = out.splitlines()[0], out.splitlines()[2]
        # Only unescaped pipes act as column delimiters.
        delimiters = lambda s: len(re.findall(r"(?<!\\)\|", s))
        assert delimiters(row) == delimiters(header)
        assert "\\|" in row  # the SAN pipe was escaped, not dropped


class TestIntegration:
    """Integration tests."""

    def test_check_row_structure(self):
        """Test that check_row returns properly structured dict."""
        with patch('dot_auditor.find_matching_ns_for_ip', return_value=[]):
            with patch('dot_auditor.tls_handshake_to_ip',
                      return_value=(False, None, None, "timeout")):
                result = dot_auditor.check_row("192.168.1.1", "example.com", 853, 5.0)

                # Verify all expected keys are present
                expected_keys = {
                    "ip", "domain", "port", "matching_ns", "sni_used",
                    "tls_ok", "error_tls", "leaf_cert_received",
                    "connected_ip", "not_before", "not_after",
                    "is_expired", "is_self_signed", "issued_by_trusted_ca",
                    "issuer_cn", "cn_list", "san_dns", "san_ips", "connected_ip_in_cert"
                }

                assert set(result.keys()) == expected_keys
                assert result["ip"] == "192.168.1.1"
                assert result["domain"] == "example.com"
                assert result["tls_ok"] is False


class TestNormalizeIP:
    """Test canonicalization of IP address text."""

    def test_uppercase_ipv6_is_lowercased(self):
        """getpeercert() emits uppercase hex digits."""
        assert dot_auditor.normalize_ip("2001:19F0:6C00::3F") == "2001:19f0:6c00::3f"

    def test_uncompressed_ipv6_is_compressed(self):
        """getpeercert() emits runs of zeroes in full."""
        assert (dot_auditor.normalize_ip("2001:41D0:305:2100:0:0:0:643A")
                == "2001:41d0:305:2100::643a")

    def test_ipv4_is_unchanged(self):
        """IPv4 already has a single textual form."""
        assert dot_auditor.normalize_ip("108.61.171.156") == "108.61.171.156"

    def test_unparseable_is_returned_verbatim(self):
        """Never discard text we failed to understand."""
        assert dot_auditor.normalize_ip("not-an-ip") == "not-an-ip"


class TestConnectedIPInCert:
    """Test that the connected address is matched against SAN IPs by value."""

    @staticmethod
    def _connected_ip_in_cert_for(peer_ip, san_ip):
        """Run check_row against a canned SAN and return connected_ip_in_cert."""
        cert = {
            "subject": (),
            "issuer": ((("commonName", "Example CA"),),),
            "subjectAltName": (("IP Address", san_ip),),
        }
        with patch('dot_auditor.find_matching_ns_for_ip', return_value=[]):
            with patch('dot_auditor.tls_handshake_to_ip',
                      return_value=(True, cert, peer_ip, None)):
                result = dot_auditor.check_row(peer_ip, "example.com", 853, 5.0)
                return result["connected_ip_in_cert"]

    def test_ipv6_matches_despite_uppercase_uncompressed_san(self):
        """The same address written two ways is still the same address."""
        assert self._connected_ip_in_cert_for(
            "2001:19f0:6c00:8501:5400:ff:fe04:3f",
            "2001:19F0:6C00:8501:5400:FF:FE04:3F",
        ) is True

    def test_ipv6_compressed_zero_run_matches(self):
        """getpeername() compresses zero runs that getpeercert() spells out."""
        assert self._connected_ip_in_cert_for(
            "2001:41d0:305:2100::643a",
            "2001:41D0:305:2100:0:0:0:643A",
        ) is True

    def test_ipv4_matches(self):
        """The IPv4 path, which never broke, keeps working."""
        assert self._connected_ip_in_cert_for("108.61.171.156", "108.61.171.156") is True

    def test_different_address_does_not_match(self):
        """A genuinely absent address still reports no."""
        assert self._connected_ip_in_cert_for("192.0.2.1", "198.51.100.1") is False


class TestSelfSigned:
    """Test is_self_signed, which compares the subject and issuer DNs."""

    @staticmethod
    def _self_signed_for(cert):
        """Run check_row against a canned certificate and return is_self_signed."""
        with patch('dot_auditor.find_matching_ns_for_ip', return_value=[]):
            with patch('dot_auditor.tls_handshake_to_ip',
                      return_value=(True, cert, "192.0.2.1", None)):
                result = dot_auditor.check_row("192.0.2.1", "example.com", 853, 5.0)
                return result["is_self_signed"]

    def test_matching_dns_is_self_signed(self):
        """Identical subject and issuer means the cert issued itself."""
        name = ((("commonName", "dns.example.com"),),)
        assert self._self_signed_for({"subject": name, "issuer": name}) is True

    def test_differing_dns_is_not_self_signed(self):
        """A leaf issued by a CA, private or public, is not self-signed."""
        cert = {
            "subject": ((("commonName", "Localhost"),),),
            "issuer": ((("commonName", "Northland Root CA"),),),
        }
        assert self._self_signed_for(cert) is False

    def test_empty_subject_is_not_self_signed(self):
        """An empty subject DN cannot equal a non-empty issuer, so the answer is no.

        Certificates that carry their names only in the SAN, such as some
        Let's Encrypt profiles, have an empty subject DN.
        """
        cert = {
            "subject": (),
            "issuer": ((("organizationName", "Let's Encrypt"),), (("commonName", "YE1"),)),
        }
        assert self._self_signed_for(cert) is False

    def test_both_dns_empty_is_unknown(self):
        """With neither DN present there is nothing to compare."""
        assert self._self_signed_for({"subject": (), "issuer": ()}) is None

    def test_absent_dns_is_unknown(self):
        """A cert dict lacking the fields entirely tells us nothing."""
        assert self._self_signed_for({"notAfter": "Jan 1 00:00:00 2030 GMT"}) is None


class TestInputValidation:
    """Test input validation and error handling."""

    def test_invalid_port_low(self, capsys):
        """Test port validation with value too low."""
        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', 'test.csv', '--port=0']):
                dot_auditor.main()

        assert exc.value.code == 1 or "Port must be between 1 and 65535" in str(exc.value.code)

    def test_invalid_port_high(self, capsys):
        """Test port validation with value too high."""
        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', 'test.csv', '--port=65536']):
                dot_auditor.main()

        assert exc.value.code == 1 or "Port must be between 1 and 65535" in str(exc.value.code)

    def test_invalid_timeout_zero(self, capsys):
        """Test timeout validation with zero value."""
        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', 'test.csv', '--timeout=0']):
                dot_auditor.main()

        assert exc.value.code == 1 or "Timeout must be positive" in str(exc.value.code)

    def test_invalid_timeout_negative(self, capsys):
        """Test timeout validation with negative value."""
        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', 'test.csv', '--timeout=-1']):
                dot_auditor.main()

        assert exc.value.code == 1 or "Timeout must be positive" in str(exc.value.code)

    def test_invalid_workers_zero(self, capsys):
        """Test workers validation with zero value."""
        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', 'test.csv', '--workers=0']):
                dot_auditor.main()

        assert exc.value.code == 1 or "Workers must be at least 1" in str(exc.value.code)

    def test_invalid_workers_negative(self, capsys):
        """Test workers validation with negative value."""
        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', 'test.csv', '--workers=-1']):
                dot_auditor.main()

        assert exc.value.code == 1 or "Workers must be at least 1" in str(exc.value.code)

    def test_invalid_ip_column(self, capsys):
        """Test IP column validation with negative value."""
        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', 'test.csv', '--ip-col=-1']):
                dot_auditor.main()

        assert exc.value.code == 1 or "Column indices must be non-negative" in str(exc.value.code)

    def test_invalid_domain_column(self, capsys):
        """Test domain column validation with negative value."""
        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', 'test.csv', '--domain-col=-1']):
                dot_auditor.main()

        assert exc.value.code == 1 or "Column indices must be non-negative" in str(exc.value.code)

    def test_file_not_found(self, capsys):
        """Test handling of non-existent CSV file."""
        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', '/nonexistent/file.csv']):
                dot_auditor.main()

        assert exc.value.code == 1 or ("File" in str(exc.value.code) and "not found" in str(exc.value.code))

    def test_empty_csv(self, tmp_path, capsys):
        """Test handling of empty CSV file."""
        empty_file = tmp_path / "empty.csv"
        empty_file.write_text("")

        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', str(empty_file)]):
                dot_auditor.main()

        assert exc.value.code == 1 or "No valid IP/domain pairs found" in str(exc.value.code)

    def test_invalid_ip_warning(self, tmp_path, capsys):
        """Test warning for invalid IP addresses in CSV."""
        csv_file = tmp_path / "invalid_ip.csv"
        csv_file.write_text("invalid-ip,example.com\n")

        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', str(csv_file)]):
                dot_auditor.main()

        assert exc.value.code == 1 or "No valid IP/domain pairs found" in str(exc.value.code)
        captured = capsys.readouterr()
        assert "Invalid IP address" in captured.err

    def test_root_domain_is_not_dropped(self, tmp_path, capsys):
        """The DNS root '.' must survive parsing, not collapse to an empty field.

        Stripping the trailing dot of a FQDN must not delete the root zone
        itself, or root-server rows are silently discarded.
        """
        csv_file = tmp_path / "root.csv"
        csv_file.write_text("170.247.170.2,.\n1.1.1.1,example.com.\n")

        def fake_check_row(ip, domain, port, timeout):
            return {"ip": ip, "domain": domain}

        with patch('dot_auditor.check_row', side_effect=fake_check_row):
            with patch('sys.argv',
                       ['dot_auditor.py', str(csv_file), '--format', 'json']):
                dot_auditor.main()

        audited = json.loads(capsys.readouterr().out)
        domains = {r["domain"] for r in audited}
        assert domains == {".", "example.com"}  # trailing dot stripped, root kept
