"""Tests for the Security Headers scanner."""

import pytest

from vulnhawk.scanners.headers import HeadersScanner


@pytest.mark.asyncio
async def test_headers_scanner_detects_missing_headers(sample_crawl_result):
    """Test that missing security headers are detected."""
    scanner = HeadersScanner()
    vulns = await scanner.scan(sample_crawl_result)

    # Should find missing security headers
    assert len(vulns) > 0

    titles = [v.title for v in vulns]

    # These headers are missing from sample_crawl_result
    assert any("Content-Security-Policy" in t for t in titles)
    assert any("X-Frame-Options" in t for t in titles)
    assert any("Strict-Transport-Security" in t for t in titles)

    # Should also detect server version disclosure
    assert any("Server Version" in t for t in titles)


@pytest.mark.asyncio
async def test_headers_scanner_passes_secure_site(secure_crawl_result):
    """Test that a properly secured site has no missing header findings."""
    scanner = HeadersScanner()
    vulns = await scanner.scan(secure_crawl_result)

    # Should have no missing security header findings
    # (may still have INFO-level findings)
    missing_header_vulns = [v for v in vulns if v.severity in ("MEDIUM", "HIGH", "CRITICAL")]
    assert len(missing_header_vulns) == 0


@pytest.mark.asyncio
async def test_csrf_scanner_detects_missing_token(sample_crawl_result):
    """Test that forms without CSRF tokens are flagged."""
    from vulnhawk.scanners.csrf import CSRFScanner

    scanner = CSRFScanner()
    vulns = await scanner.scan(sample_crawl_result)

    # The login form is POST without CSRF token
    assert len(vulns) >= 1
    assert any("CSRF" in v.title for v in vulns)
    assert all(v.severity == "MEDIUM" for v in vulns)
