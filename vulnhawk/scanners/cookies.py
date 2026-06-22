"""Cookie Security Scanner — checks cookie attributes for security issues."""

from vulnhawk.core.crawler import CrawlResult
from vulnhawk.core.scanner import BaseScanner, Vulnerability, register_scanner


@register_scanner
class CookieScanner(BaseScanner):
    """Checks cookies for missing security flags."""

    name = "Cookie Security Scanner"
    description = "Analyzes cookies for HttpOnly, Secure, SameSite flags"

    async def scan(self, target: CrawlResult) -> list[Vulnerability]:
        vulnerabilities = []

        # Check cookies from the base URL response headers
        base_headers = target.headers.get(target.base_url, {})
        set_cookie_headers = []

        # Collect all Set-Cookie headers
        for url, headers in target.headers.items():
            for key, value in headers.items():
                if key.lower() == "set-cookie":
                    set_cookie_headers.append((url, value))

        for url, cookie_header in set_cookie_headers:
            cookie_name = cookie_header.split("=")[0].strip() if "=" in cookie_header else "unknown"
            cookie_lower = cookie_header.lower()

            # Check for missing HttpOnly flag
            if "httponly" not in cookie_lower:
                vulnerabilities.append(Vulnerability(
                    title=f"Cookie '{cookie_name}' Missing HttpOnly Flag",
                    severity="LOW",
                    url=url,
                    description=(
                        f"The cookie '{cookie_name}' does not have the HttpOnly flag. "
                        f"This means it can be accessed via JavaScript, making it vulnerable "
                        f"to theft via XSS attacks."
                    ),
                    evidence=f"Set-Cookie: {cookie_header}",
                    remediation="Add the HttpOnly flag to prevent JavaScript access to the cookie.",
                    cvss_score=3.7,
                ))

            # Check for missing Secure flag
            if "secure" not in cookie_lower:
                vulnerabilities.append(Vulnerability(
                    title=f"Cookie '{cookie_name}' Missing Secure Flag",
                    severity="LOW",
                    url=url,
                    description=(
                        f"The cookie '{cookie_name}' does not have the Secure flag. "
                        f"It may be transmitted over unencrypted HTTP connections."
                    ),
                    evidence=f"Set-Cookie: {cookie_header}",
                    remediation="Add the Secure flag to ensure the cookie is only sent over HTTPS.",
                    cvss_score=3.1,
                ))

            # Check for missing SameSite attribute
            if "samesite" not in cookie_lower:
                vulnerabilities.append(Vulnerability(
                    title=f"Cookie '{cookie_name}' Missing SameSite Attribute",
                    severity="LOW",
                    url=url,
                    description=(
                        f"The cookie '{cookie_name}' does not have the SameSite attribute. "
                        f"This may make the application vulnerable to CSRF attacks."
                    ),
                    evidence=f"Set-Cookie: {cookie_header}",
                    remediation="Add SameSite=Lax or SameSite=Strict to prevent CSRF.",
                    cvss_score=4.3,
                ))

        return vulnerabilities
