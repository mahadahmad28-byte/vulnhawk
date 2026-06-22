"""SSL/TLS Certificate and Configuration Scanner."""

import socket
import ssl
from datetime import datetime, timezone

from vulnhawk.core.crawler import CrawlResult
from vulnhawk.core.scanner import BaseScanner, Vulnerability, register_scanner


@register_scanner
class SSLTLSScanner(BaseScanner):
    """Checks SSL/TLS certificate validity and security configuration."""

    name = "SSL/TLS Scanner"
    description = "Checks certificate expiry, weak protocols, and TLS misconfigurations"

    async def scan(self, target: CrawlResult) -> list[Vulnerability]:
        vulnerabilities = []

        # Only meaningful for HTTPS targets
        from urllib.parse import urlparse
        parsed = urlparse(target.base_url)

        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # Check HTTP (no TLS at all) — on a production site this is a problem
        if parsed.scheme == "http":
            vulnerabilities.append(Vulnerability(
                title="Site Served Over HTTP (No TLS)",
                severity="HIGH",
                url=target.base_url,
                description=(
                    "The site is served over plain HTTP without encryption. "
                    "All traffic between the user and server is transmitted in cleartext, "
                    "making it vulnerable to eavesdropping and MITM attacks."
                ),
                evidence="URL scheme: http:// (not https://)",
                remediation=(
                    "Obtain a free TLS certificate from Let's Encrypt and configure "
                    "your web server to serve all traffic over HTTPS. "
                    "Redirect all HTTP requests to HTTPS."
                ),
                cvss_score=7.5,
                references=[
                    "https://letsencrypt.org/getting-started/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                ],
            ))
            return vulnerabilities

        # For HTTPS, check the certificate
        try:
            cert_vulns = self._check_certificate(hostname, port)
            vulnerabilities.extend(cert_vulns)
        except Exception:
            # Can't connect to check TLS — skip silently
            pass

        return vulnerabilities

    def _check_certificate(self, hostname: str, port: int) -> list[Vulnerability]:
        """Connect and inspect the TLS certificate."""
        vulns = []

        # Create default SSL context
        context = ssl.create_default_context()

        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher_name, _, _ = ssock.cipher()

                    # Check certificate expiry
                    not_after_str = cert.get("notAfter", "")
                    if not_after_str:
                        not_after = datetime.strptime(
                            not_after_str, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        days_left = (not_after - now).days

                        if days_left < 0:
                            vulns.append(Vulnerability(
                                title="SSL Certificate Expired",
                                severity="CRITICAL",
                                url=f"https://{hostname}:{port}",
                                description=(
                                    f"The SSL certificate expired {abs(days_left)} days ago. "
                                    f"Browsers will show a security warning to all visitors."
                                ),
                                evidence=f"Certificate expired: {not_after_str}",
                                remediation="Renew the certificate immediately. Use Let's Encrypt for free auto-renewal.",
                                cvss_score=7.5,
                            ))
                        elif days_left < 30:
                            vulns.append(Vulnerability(
                                title=f"SSL Certificate Expiring Soon ({days_left} days)",
                                severity="MEDIUM",
                                url=f"https://{hostname}:{port}",
                                description=(
                                    f"The SSL certificate expires in {days_left} days. "
                                    f"Failure to renew will cause browser security warnings."
                                ),
                                evidence=f"Certificate expires: {not_after_str}",
                                remediation="Renew the certificate before expiry. Set up auto-renewal with certbot.",
                                cvss_score=5.3,
                            ))

                    # Check for weak TLS protocols
                    if protocol in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                        vulns.append(Vulnerability(
                            title=f"Weak TLS Protocol in Use: {protocol}",
                            severity="HIGH",
                            url=f"https://{hostname}:{port}",
                            description=(
                                f"The server supports the deprecated {protocol} protocol, "
                                f"which has known vulnerabilities (POODLE, BEAST, etc.)."
                            ),
                            evidence=f"Negotiated protocol: {protocol}",
                            remediation=(
                                "Disable TLS 1.0 and 1.1. Only allow TLS 1.2 and TLS 1.3. "
                                "Update your web server's SSL configuration."
                            ),
                            cvss_score=7.4,
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                            ],
                        ))

                    # Check for weak ciphers
                    weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]
                    for weak in weak_ciphers:
                        if weak in cipher_name.upper():
                            vulns.append(Vulnerability(
                                title=f"Weak Cipher Suite in Use: {cipher_name}",
                                severity="HIGH",
                                url=f"https://{hostname}:{port}",
                                description=(
                                    f"The cipher suite '{cipher_name}' is considered weak "
                                    f"and may be vulnerable to cryptographic attacks."
                                ),
                                evidence=f"Negotiated cipher: {cipher_name}",
                                remediation=(
                                    "Configure your server to only use strong cipher suites. "
                                    "Prefer ECDHE and AES-GCM ciphers. Disable RC4, DES, 3DES."
                                ),
                                cvss_score=7.4,
                            ))
                            break

        except ssl.SSLCertVerificationError as e:
            vulns.append(Vulnerability(
                title="SSL Certificate Verification Failed",
                severity="HIGH",
                url=f"https://{hostname}:{port}",
                description=(
                    "The SSL certificate could not be verified. It may be self-signed, "
                    "expired, or the hostname may not match the certificate."
                ),
                evidence=str(e),
                remediation=(
                    "Use a certificate from a trusted Certificate Authority (CA). "
                    "Let's Encrypt provides free, trusted certificates."
                ),
                cvss_score=7.4,
            ))
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass  # Target not reachable on port 443

        return vulns
