"""XSS (Cross-Site Scripting) Scanner — detects reflected XSS vulnerabilities."""

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from vulnhawk.core.crawler import CrawlResult
from vulnhawk.core.scanner import BaseScanner, Vulnerability, register_scanner

# Test payloads for XSS detection
XSS_PAYLOADS = [
    '<script>alert("VH")</script>',
    '"><img src=x onerror=alert("VH")>',
    "'-alert('VH')-'",
    "<svg/onload=alert('VH')>",
    '"><svg/onload=alert("VH")>',
    "javascript:alert('VH')",
    '<img src="x" onerror="alert(1)">',
    "{{7*7}}",  # Template injection check
]

# Patterns that indicate successful XSS reflection
REFLECTION_INDICATORS = [
    '<script>alert("VH")</script>',
    'onerror=alert("VH")',
    "onerror=alert('VH')",
    "onload=alert('VH')",
    "alert('VH')",
    "{{49}}",  # Template injection result
]


@register_scanner
class XSSScanner(BaseScanner):
    """Scans for reflected Cross-Site Scripting (XSS) vulnerabilities."""

    name = "XSS Scanner"
    description = "Tests URL parameters and form inputs for reflected XSS"

    async def scan(self, target: CrawlResult) -> list[Vulnerability]:
        vulnerabilities = []

        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "VulnHawk/1.0 Security Scanner"},
        ) as client:

            # Test URL parameters
            for url, params in target.parameters.items():
                for param in params:
                    for payload in XSS_PAYLOADS:
                        vuln = await self._test_param(client, url, param, payload)
                        if vuln:
                            vulnerabilities.append(vuln)
                            break  # One finding per param is enough

            # Test form inputs
            for form in target.forms:
                for input_field in form.inputs:
                    if input_field["type"] in ("hidden", "submit", "button"):
                        continue
                    for payload in XSS_PAYLOADS[:3]:  # Test fewer payloads for forms
                        vuln = await self._test_form(client, form, input_field, payload)
                        if vuln:
                            vulnerabilities.append(vuln)
                            break

        return vulnerabilities

    async def _test_param(
        self, client: httpx.AsyncClient, url: str, param: str, payload: str
    ) -> Vulnerability | None:
        """Test a URL parameter for reflected XSS."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        query_params[param] = [payload]

        # Rebuild URL with injected payload
        new_query = urlencode(query_params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        try:
            response = await client.get(test_url)
            body = response.text.lower()

            for indicator in REFLECTION_INDICATORS:
                if indicator.lower() in body:
                    return Vulnerability(
                        title=f"Reflected XSS in parameter '{param}'",
                        severity="HIGH",
                        url=url,
                        description=(
                            f"The parameter '{param}' reflects user input without proper "
                            f"sanitization, allowing JavaScript execution in the victim's browser."
                        ),
                        evidence=f"Payload: {payload} | Reflected in response body",
                        remediation=(
                            "Encode all user input before rendering in HTML. "
                            "Use Content-Security-Policy headers. "
                            "Implement input validation and output encoding."
                        ),
                        cvss_score=7.2,
                        references=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                        ],
                    )
        except (httpx.RequestError, httpx.HTTPStatusError):
            pass

        return None

    async def _test_form(
        self, client: httpx.AsyncClient, form, input_field: dict, payload: str
    ) -> Vulnerability | None:
        """Test a form input for reflected XSS."""
        # Build form data with the payload
        form_data = {}
        for inp in form.inputs:
            if inp["name"] == input_field["name"]:
                form_data[inp["name"]] = payload
            else:
                form_data[inp["name"]] = inp.get("value", "test")

        try:
            if form.method == "POST":
                response = await client.post(form.action, data=form_data)
            else:
                response = await client.get(form.action, params=form_data)

            body = response.text.lower()

            for indicator in REFLECTION_INDICATORS:
                if indicator.lower() in body:
                    return Vulnerability(
                        title=f"Reflected XSS in form input '{input_field['name']}'",
                        severity="HIGH",
                        url=form.url,
                        description=(
                            f"The form input '{input_field['name']}' at {form.action} "
                            f"reflects user input without sanitization."
                        ),
                        evidence=f"Payload: {payload} | Form action: {form.action}",
                        remediation=(
                            "Sanitize and encode all form input before rendering. "
                            "Use Content-Security-Policy headers."
                        ),
                        cvss_score=6.1,
                    )
        except (httpx.RequestError, httpx.HTTPStatusError):
            pass

        return None
