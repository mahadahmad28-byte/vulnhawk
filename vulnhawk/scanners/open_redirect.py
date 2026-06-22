"""Open Redirect Scanner — detects URL redirection vulnerabilities."""

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from vulnhawk.core.crawler import CrawlResult
from vulnhawk.core.scanner import BaseScanner, Vulnerability, register_scanner

# Common parameter names that handle redirects
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "returnTo", "next", "next_url", "target", "dest", "destination",
    "redir", "redirect_to", "go", "goto", "link", "forward", "continue",
    "callback", "path", "out", "ref",
]

# External URL to test redirection
TEST_REDIRECT_URL = "https://evil.com"


@register_scanner
class OpenRedirectScanner(BaseScanner):
    """Detects open redirect vulnerabilities in URL parameters."""

    name = "Open Redirect Scanner"
    description = "Tests URL parameters for open redirect vulnerabilities"

    async def scan(self, target: CrawlResult) -> list[Vulnerability]:
        vulnerabilities = []

        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=False,  # Don't follow — we want to see the redirect
            verify=False,
            headers={"User-Agent": "VulnHawk/1.0 Security Scanner"},
        ) as client:

            # Test known redirect parameters in discovered URLs
            for url, params in target.parameters.items():
                for param in params:
                    if param.lower() in REDIRECT_PARAMS:
                        vuln = await self._test_redirect(client, url, param)
                        if vuln:
                            vulnerabilities.append(vuln)

            # Also test common redirect params even if not discovered in crawl
            for url in target.urls[:10]:  # Test first 10 URLs
                for param in REDIRECT_PARAMS[:10]:  # Test most common params
                    vuln = await self._test_redirect(client, url, param)
                    if vuln:
                        vulnerabilities.append(vuln)
                        break  # One per URL is enough

        return vulnerabilities

    async def _test_redirect(
        self, client: httpx.AsyncClient, url: str, param: str
    ) -> Vulnerability | None:
        """Test a URL parameter for open redirect."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        query_params[param] = [TEST_REDIRECT_URL]
        new_query = urlencode(query_params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        try:
            response = await client.get(test_url)

            # Check if it redirects to our evil URL
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location", "")
                if "evil.com" in location:
                    return Vulnerability(
                        title=f"Open Redirect via '{param}' Parameter",
                        severity="MEDIUM",
                        url=url,
                        description=(
                            f"The parameter '{param}' can redirect users to arbitrary "
                            f"external URLs. Attackers can use this for phishing by crafting "
                            f"links that appear to be from your domain."
                        ),
                        evidence=f"Payload: {param}={TEST_REDIRECT_URL} → Location: {location}",
                        remediation=(
                            "Validate redirect URLs against a whitelist of allowed domains. "
                            "Use relative paths instead of full URLs for redirects. "
                            "Never trust user input for redirect destinations."
                        ),
                        cvss_score=6.1,
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                        ],
                    )
        except (httpx.RequestError, httpx.HTTPStatusError):
            pass

        return None
