"""Security Headers Analyzer — checks for missing or misconfigured HTTP security headers."""

from vulnhawk.core.crawler import CrawlResult
from vulnhawk.core.scanner import BaseScanner, Vulnerability, register_scanner

# Required security headers and their descriptions
SECURITY_HEADERS = {
    "content-security-policy": {
        "severity": "MEDIUM",
        "title": "Missing Content-Security-Policy (CSP) Header",
        "description": (
            "Content-Security-Policy header is not set. This header helps prevent "
            "XSS, clickjacking, and other code injection attacks by specifying "
            "allowed content sources."
        ),
        "remediation": (
            "Add a Content-Security-Policy header. Start with: "
            "Content-Security-Policy: default-src 'self'; script-src 'self'"
        ),
        "cvss_score": 6.1,
    },
    "x-frame-options": {
        "severity": "MEDIUM",
        "title": "Missing X-Frame-Options Header",
        "description": (
            "X-Frame-Options header is not set. The site may be vulnerable to "
            "clickjacking attacks where it can be loaded in an iframe."
        ),
        "remediation": "Add header: X-Frame-Options: DENY (or SAMEORIGIN)",
        "cvss_score": 5.4,
    },
    "strict-transport-security": {
        "severity": "MEDIUM",
        "title": "Missing Strict-Transport-Security (HSTS) Header",
        "description": (
            "HSTS header is not set. Browsers won't enforce HTTPS connections, "
            "leaving users vulnerable to protocol downgrade and MITM attacks."
        ),
        "remediation": (
            "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
        ),
        "cvss_score": 5.9,
    },
    "x-content-type-options": {
        "severity": "LOW",
        "title": "Missing X-Content-Type-Options Header",
        "description": (
            "X-Content-Type-Options header is not set. Browsers may try to MIME-sniff "
            "the content type, potentially leading to security issues."
        ),
        "remediation": "Add header: X-Content-Type-Options: nosniff",
        "cvss_score": 4.3,
    },
    "x-xss-protection": {
        "severity": "LOW",
        "title": "Missing X-XSS-Protection Header",
        "description": (
            "X-XSS-Protection header is not set. While modern browsers have built-in "
            "XSS protection, this header provides an additional layer."
        ),
        "remediation": "Add header: X-XSS-Protection: 1; mode=block",
        "cvss_score": 3.7,
    },
    "referrer-policy": {
        "severity": "LOW",
        "title": "Missing Referrer-Policy Header",
        "description": (
            "Referrer-Policy header is not set. The browser may send the full URL "
            "as a referrer, potentially leaking sensitive information."
        ),
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
        "cvss_score": 3.1,
    },
    "permissions-policy": {
        "severity": "LOW",
        "title": "Missing Permissions-Policy Header",
        "description": (
            "Permissions-Policy (formerly Feature-Policy) is not set. Browser features "
            "like camera, microphone, and geolocation are not restricted."
        ),
        "remediation": (
            "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()"
        ),
        "cvss_score": 2.4,
    },
}

# Headers that shouldn't be present (information disclosure)
DANGEROUS_HEADERS = {
    "server": {
        "severity": "INFO",
        "title": "Server Version Disclosed",
        "description": "The Server header reveals the web server software and version.",
        "remediation": "Remove or obfuscate the Server header to prevent information disclosure.",
        "cvss_score": 2.0,
    },
    "x-powered-by": {
        "severity": "INFO",
        "title": "Technology Stack Disclosed via X-Powered-By",
        "description": "The X-Powered-By header reveals the technology stack.",
        "remediation": "Remove the X-Powered-By header.",
        "cvss_score": 2.0,
    },
    "x-aspnet-version": {
        "severity": "INFO",
        "title": "ASP.NET Version Disclosed",
        "description": "The X-AspNet-Version header reveals the ASP.NET framework version.",
        "remediation": "Remove the X-AspNet-Version header.",
        "cvss_score": 2.0,
    },
}


@register_scanner
class HeadersScanner(BaseScanner):
    """Analyzes HTTP response headers for security misconfigurations."""

    name = "Security Headers Analyzer"
    description = "Checks for missing or misconfigured HTTP security headers"

    async def scan(self, target: CrawlResult) -> list[Vulnerability]:
        vulnerabilities = []

        # Only check headers on the main page (base URL)
        base_headers = target.headers.get(target.base_url, {})

        if not base_headers:
            # Try first URL if base URL headers not available
            if target.urls:
                base_headers = target.headers.get(target.urls[0], {})

        if not base_headers:
            return vulnerabilities

        # Normalize header names to lowercase
        headers_lower = {k.lower(): v for k, v in base_headers.items()}

        # Check for missing security headers
        for header_name, header_info in SECURITY_HEADERS.items():
            if header_name not in headers_lower:
                vulnerabilities.append(Vulnerability(
                    title=header_info["title"],
                    severity=header_info["severity"],
                    url=target.base_url,
                    description=header_info["description"],
                    evidence=f"Header '{header_name}' is not present in the response",
                    remediation=header_info["remediation"],
                    cvss_score=header_info.get("cvss_score"),
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header_name}",
                    ],
                ))

        # Check for dangerous information disclosure headers
        for header_name, header_info in DANGEROUS_HEADERS.items():
            if header_name in headers_lower:
                value = headers_lower[header_name]
                vulnerabilities.append(Vulnerability(
                    title=header_info["title"],
                    severity=header_info["severity"],
                    url=target.base_url,
                    description=header_info["description"],
                    evidence=f"{header_name}: {value}",
                    remediation=header_info["remediation"],
                    cvss_score=header_info.get("cvss_score"),
                ))

        return vulnerabilities
