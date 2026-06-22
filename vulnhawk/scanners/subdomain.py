"""Subdomain Enumeration Scanner — discovers live subdomains of the target domain."""

import asyncio
import socket
from urllib.parse import urlparse

import httpx

from vulnhawk.core.crawler import CrawlResult
from vulnhawk.core.scanner import BaseScanner, Vulnerability, register_scanner

# Common subdomain prefixes to probe
COMMON_SUBDOMAINS = [
    "www", "api", "app", "admin", "dashboard", "portal", "dev", "staging",
    "stage", "test", "qa", "uat", "demo", "beta", "alpha", "preview",
    "mail", "smtp", "imap", "webmail", "email",
    "ftp", "sftp", "files", "cdn", "static", "assets", "media", "img",
    "vpn", "remote", "gateway", "proxy", "lb", "load", "backend",
    "db", "database", "mysql", "mongo", "redis", "elastic",
    "git", "gitlab", "github", "jenkins", "ci", "build", "deploy",
    "docs", "doc", "wiki", "help", "support", "status",
    "shop", "store", "payment", "checkout", "billing", "account",
    "login", "auth", "sso", "oauth", "id",
    "m", "mobile", "wap", "old", "new", "v2", "v1",
    "internal", "intranet", "corp", "staff",
    "monitoring", "grafana", "kibana", "prometheus",
]


@register_scanner
class SubdomainScanner(BaseScanner):
    """Enumerates common subdomains of the target domain via DNS + HTTP probe."""

    name = "Subdomain Enumerator"
    description = "Probes common subdomain prefixes for live hosts"

    async def scan(self, target: CrawlResult) -> list[Vulnerability]:
        vulnerabilities = []

        parsed = urlparse(target.base_url)
        hostname = parsed.hostname or ""

        # Extract root domain (e.g., example.com from www.example.com)
        parts = hostname.split(".")
        if len(parts) < 2:
            return vulnerabilities  # Can't enumerate subdomains without a valid domain

        # Root domain = last two parts (handles example.com, not *.co.uk)
        root_domain = ".".join(parts[-2:])

        # Don't enumerate localhost or IP addresses
        if root_domain in ("localhost", "127.0.0.1") or parts[-1].isdigit():
            return vulnerabilities

        semaphore = asyncio.Semaphore(20)

        async def probe_subdomain(subdomain: str) -> Vulnerability | None:
            """Check if subdomain resolves and responds to HTTP."""
            fqdn = f"{subdomain}.{root_domain}"
            url = f"{parsed.scheme}://{fqdn}"

            async with semaphore:
                # DNS check first (fast)
                try:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, socket.gethostbyname, fqdn)
                except socket.gaierror:
                    return None  # No DNS record — subdomain doesn't exist

                # HTTP probe
                try:
                    async with httpx.AsyncClient(
                        timeout=5.0,
                        follow_redirects=True,
                        verify=False,
                        headers={"User-Agent": "VulnHawk/1.0 Security Scanner"},
                    ) as client:
                        response = await client.get(url)
                        status = response.status_code

                        # Determine severity based on what we found
                        sensitive_keywords = ["admin", "dashboard", "internal", "staging", "dev",
                                              "db", "database", "git", "jenkins", "grafana",
                                              "kibana", "monitoring", "vpn", "mail", "smtp"]
                        is_sensitive = any(kw in subdomain.lower() for kw in sensitive_keywords)

                        return Vulnerability(
                            title=f"Live Subdomain Discovered: {fqdn}",
                            severity="MEDIUM" if is_sensitive else "INFO",
                            url=url,
                            description=(
                                f"The subdomain '{fqdn}' is live and responded with HTTP {status}. "
                                + (
                                    f"This appears to be a sensitive subdomain ({subdomain}) that may "
                                    f"expose internal services or administrative interfaces."
                                    if is_sensitive
                                    else f"Each subdomain expands your attack surface."
                                )
                            ),
                            evidence=f"DNS resolved: {fqdn} | HTTP {status} at {url}",
                            remediation=(
                                "Ensure this subdomain is intentionally public. "
                                "Remove or restrict access to internal/staging subdomains. "
                                "Apply the same security controls as the main domain."
                            ),
                            cvss_score=5.3 if is_sensitive else 2.0,
                            scanner_name=self.name,
                        )

                except (httpx.RequestError, httpx.HTTPStatusError):
                    # DNS resolved but HTTP failed — still worth noting
                    return Vulnerability(
                        title=f"Subdomain Resolves (No HTTP): {fqdn}",
                        severity="INFO",
                        url=url,
                        description=(
                            f"The subdomain '{fqdn}' has a DNS record but did not respond to HTTP. "
                            f"It may host a non-HTTP service (FTP, SSH, database, etc.)."
                        ),
                        evidence=f"DNS resolved: {fqdn} | No HTTP response",
                        remediation=(
                            "Verify this subdomain is intentional. "
                            "Ensure any services running here are properly secured."
                        ),
                        cvss_score=2.0,
                        scanner_name=self.name,
                    )

        # Probe all subdomains concurrently
        tasks = [probe_subdomain(sub) for sub in COMMON_SUBDOMAINS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Vulnerability):
                vulnerabilities.append(result)

        # Sort: MEDIUM first, then INFO
        severity_order = {"MEDIUM": 0, "INFO": 1}
        vulnerabilities.sort(key=lambda v: severity_order.get(v.severity, 2))

        return vulnerabilities
