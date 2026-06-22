"""CSRF Scanner — checks forms for missing Cross-Site Request Forgery protections."""

from vulnhawk.core.crawler import CrawlResult
from vulnhawk.core.scanner import BaseScanner, Vulnerability, register_scanner

# Common CSRF token field names
CSRF_TOKEN_NAMES = {
    "csrf", "csrf_token", "csrftoken", "_csrf", "csrfmiddlewaretoken",
    "authenticity_token", "_token", "token", "anti_csrf", "xsrf",
    "xsrf_token", "_xsrf", "request_verification_token",
    "__requestverificationtoken", "antiforgery",
}


@register_scanner
class CSRFScanner(BaseScanner):
    """Checks forms for missing CSRF protection tokens."""

    name = "CSRF Scanner"
    description = "Checks POST forms for anti-CSRF tokens"

    async def scan(self, target: CrawlResult) -> list[Vulnerability]:
        vulnerabilities = []

        for form in target.forms:
            # Only check POST forms (GET forms are less risky for CSRF)
            if form.method != "POST":
                continue

            # Check if any input field looks like a CSRF token
            has_csrf_token = False
            for input_field in form.inputs:
                name = input_field.get("name", "").lower()
                input_type = input_field.get("type", "").lower()

                if name in CSRF_TOKEN_NAMES:
                    has_csrf_token = True
                    break
                if input_type == "hidden" and any(token_name in name for token_name in CSRF_TOKEN_NAMES):
                    has_csrf_token = True
                    break

            if not has_csrf_token:
                input_names = [i["name"] for i in form.inputs if i.get("name")]
                vulnerabilities.append(Vulnerability(
                    title="Missing CSRF Protection on Form",
                    severity="MEDIUM",
                    url=form.url,
                    description=(
                        f"A POST form at {form.action} does not appear to have "
                        f"CSRF token protection. An attacker could trick authenticated "
                        f"users into submitting this form from a malicious website."
                    ),
                    evidence=(
                        f"Form action: {form.action} | Method: {form.method} | "
                        f"Fields: {', '.join(input_names)}"
                    ),
                    remediation=(
                        "Add a CSRF token to all POST forms. Use your framework's built-in "
                        "CSRF protection (e.g., Django's {% csrf_token %}, Express's csurf). "
                        "Validate the token on the server for every state-changing request."
                    ),
                    cvss_score=6.5,
                    references=[
                        "https://owasp.org/www-community/attacks/csrf",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                    ],
                ))

        return vulnerabilities
