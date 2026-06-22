"""SQL Injection Scanner — detects error-based and boolean-based SQLi vulnerabilities."""

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from vulnhawk.core.crawler import CrawlResult
from vulnhawk.core.scanner import BaseScanner, Vulnerability, register_scanner

# SQL injection test payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
    "1' ORDER BY 1--",
    "1' UNION SELECT NULL--",
    "'; DROP TABLE users--",
    "1 OR 1=1",
    "' AND 1=CONVERT(int, (SELECT @@version))--",
    "1' WAITFOR DELAY '0:0:3'--",  # Time-based (blind)
]

# Database error messages that indicate SQLi
SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql_",
    "unclosed quotation mark",
    "microsoft ole db provider for sql server",
    "syntax error",
    "pg_query",
    "postgresql",
    "ora-01756",
    "oracle error",
    "sqlite3.operationalerror",
    "sqliteexception",
    "sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "unterminated string",
    "quoted string not properly terminated",
    "microsoft sql native client error",
    "odbc sql server driver",
    "invalid query",
    "sql command not properly ended",
]


@register_scanner
class SQLInjectionScanner(BaseScanner):
    """Scans for SQL injection vulnerabilities in URL parameters and form inputs."""

    name = "SQL Injection Scanner"
    description = "Tests for error-based, boolean-based, and time-based SQL injection"

    async def scan(self, target: CrawlResult) -> list[Vulnerability]:
        vulnerabilities = []

        async with httpx.AsyncClient(
            timeout=15.0,  # Higher timeout for time-based tests
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "VulnHawk/1.0 Security Scanner"},
        ) as client:

            # Test URL parameters
            for url, params in target.parameters.items():
                for param in params:
                    vuln = await self._test_param(client, url, param)
                    if vuln:
                        vulnerabilities.append(vuln)

            # Test form inputs
            for form in target.forms:
                for input_field in form.inputs:
                    if input_field["type"] in ("hidden", "submit", "button", "checkbox"):
                        continue
                    vuln = await self._test_form(client, form, input_field)
                    if vuln:
                        vulnerabilities.append(vuln)

        return vulnerabilities

    async def _test_param(
        self, client: httpx.AsyncClient, url: str, param: str
    ) -> Vulnerability | None:
        """Test a URL parameter for SQL injection."""

        # Get baseline response
        try:
            baseline = await client.get(url)
            baseline_length = len(baseline.text)
        except (httpx.RequestError, httpx.HTTPStatusError):
            return None

        for payload in SQLI_PAYLOADS:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            query_params[param] = [payload]
            new_query = urlencode(query_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                # Check for time-based SQLi
                if "WAITFOR" in payload or "SLEEP" in payload:
                    import time
                    start = time.time()
                    response = await client.get(test_url)
                    elapsed = time.time() - start

                    if elapsed >= 2.5:  # Delay was executed
                        return Vulnerability(
                            title=f"Time-Based Blind SQL Injection in '{param}'",
                            severity="CRITICAL",
                            url=url,
                            description=(
                                f"The parameter '{param}' is vulnerable to time-based blind "
                                f"SQL injection. The server delayed its response by ~{elapsed:.1f}s "
                                f"when injected with a time delay payload."
                            ),
                            evidence=f"Payload: {payload} | Response delay: {elapsed:.1f}s",
                            remediation=(
                                "Use parameterized queries (prepared statements). "
                                "Never concatenate user input into SQL queries. "
                                "Use an ORM like SQLAlchemy. "
                                "Apply input validation and whitelist allowed characters."
                            ),
                            cvss_score=9.8,
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            ],
                        )
                    continue

                response = await client.get(test_url)
                body = response.text.lower()

                # Check for SQL error messages (error-based SQLi)
                for error_pattern in SQL_ERROR_PATTERNS:
                    if error_pattern in body:
                        return Vulnerability(
                            title=f"Error-Based SQL Injection in '{param}'",
                            severity="CRITICAL",
                            url=url,
                            description=(
                                f"The parameter '{param}' is vulnerable to SQL injection. "
                                f"Database error messages are exposed in the response."
                            ),
                            evidence=f"Payload: {payload} | Error pattern: '{error_pattern}'",
                            remediation=(
                                "Use parameterized queries. Never concatenate user input "
                                "into SQL queries. Disable detailed error messages in production."
                            ),
                            cvss_score=9.8,
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                            ],
                        )

                # Check for boolean-based SQLi (significant response length change)
                if abs(len(response.text) - baseline_length) > baseline_length * 0.3:
                    if "OR" in payload and "1" in payload:
                        return Vulnerability(
                            title=f"Boolean-Based SQL Injection in '{param}'",
                            severity="HIGH",
                            url=url,
                            description=(
                                f"The parameter '{param}' shows different responses for "
                                f"true/false SQL conditions, suggesting boolean-based SQLi."
                            ),
                            evidence=(
                                f"Payload: {payload} | "
                                f"Baseline length: {baseline_length} | "
                                f"Injected length: {len(response.text)}"
                            ),
                            remediation="Use parameterized queries and input validation.",
                            cvss_score=8.1,
                        )

            except (httpx.RequestError, httpx.HTTPStatusError):
                continue

        return None

    async def _test_form(
        self, client: httpx.AsyncClient, form, input_field: dict
    ) -> Vulnerability | None:
        """Test a form input for SQL injection."""
        for payload in SQLI_PAYLOADS[:5]:  # Test fewer payloads for forms
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

                for error_pattern in SQL_ERROR_PATTERNS:
                    if error_pattern in body:
                        return Vulnerability(
                            title=f"SQL Injection in form input '{input_field['name']}'",
                            severity="CRITICAL",
                            url=form.url,
                            description=(
                                f"The form input '{input_field['name']}' at {form.action} "
                                f"is vulnerable to SQL injection."
                            ),
                            evidence=f"Payload: {payload} | Error: '{error_pattern}'",
                            remediation="Use parameterized queries and input validation.",
                            cvss_score=9.8,
                        )
            except (httpx.RequestError, httpx.HTTPStatusError):
                continue

        return None
