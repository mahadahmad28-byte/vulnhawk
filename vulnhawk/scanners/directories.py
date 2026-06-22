"""Directory Enumerator — brute-force common sensitive paths and files."""

import httpx

from vulnhawk.core.crawler import CrawlResult
from vulnhawk.core.scanner import BaseScanner, Vulnerability, register_scanner

# Common sensitive directories and files to check
SENSITIVE_PATHS = [
    # Version control
    "/.git/HEAD",
    "/.git/config",
    "/.svn/entries",
    # Environment and config files
    "/.env",
    "/.env.local",
    "/.env.production",
    "/config.php",
    "/config.yml",
    "/wp-config.php",
    "/configuration.php",
    # Admin panels
    "/admin",
    "/admin/login",
    "/administrator",
    "/wp-admin",
    "/phpmyadmin",
    "/cpanel",
    "/dashboard",
    # Backup files
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/database.sql",
    "/dump.sql",
    "/backup.tar.gz",
    # Debug and info
    "/debug",
    "/info.php",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
    "/.htaccess",
    "/.htpasswd",
    # API docs (not necessarily bad, but useful to know)
    "/api",
    "/api/docs",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/graphql",
    # Common frameworks
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/.well-known/security.txt",
]

# Status codes that indicate the path exists
FOUND_STATUS_CODES = {200, 301, 302, 307, 308, 401, 403}


@register_scanner
class DirectoryScanner(BaseScanner):
    """Enumerates common sensitive directories and files."""

    name = "Directory Enumerator"
    description = "Brute-forces common sensitive paths, backup files, and admin panels"

    async def scan(self, target: CrawlResult) -> list[Vulnerability]:
        vulnerabilities = []
        base_url = target.base_url.rstrip("/")

        async with httpx.AsyncClient(
            timeout=5.0,
            follow_redirects=False,  # Don't follow redirects for directory enum
            verify=False,
            headers={"User-Agent": "VulnHawk/1.0 Security Scanner"},
        ) as client:

            for path in SENSITIVE_PATHS:
                test_url = f"{base_url}{path}"

                try:
                    response = await client.get(test_url)

                    if response.status_code in FOUND_STATUS_CODES:
                        vuln = self._classify_finding(path, test_url, response.status_code)
                        if vuln:
                            vulnerabilities.append(vuln)

                except (httpx.RequestError, httpx.HTTPStatusError):
                    continue

        return vulnerabilities

    def _classify_finding(self, path: str, url: str, status: int) -> Vulnerability | None:
        """Classify a found path by severity and type."""

        # Git exposure — critical
        if ".git" in path:
            return Vulnerability(
                title="Git Repository Exposed",
                severity="CRITICAL",
                url=url,
                description=(
                    "The .git directory is publicly accessible. An attacker can download "
                    "the entire source code, including commit history, credentials, and secrets."
                ),
                evidence=f"HTTP {status} at {url}",
                remediation="Block access to .git directories in your web server configuration.",
                cvss_score=9.1,
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"],
            )

        # Environment files — critical
        if ".env" in path:
            return Vulnerability(
                title="Environment File Exposed",
                severity="CRITICAL",
                url=url,
                description=(
                    "An environment file (.env) is publicly accessible. These files typically "
                    "contain database credentials, API keys, and secret tokens."
                ),
                evidence=f"HTTP {status} at {url}",
                remediation="Move .env files outside the web root or block access via server config.",
                cvss_score=9.1,
            )

        # Database dumps — critical
        if any(ext in path for ext in [".sql", "dump", "backup"]):
            if status == 200:
                return Vulnerability(
                    title="Database Backup File Exposed",
                    severity="CRITICAL",
                    url=url,
                    description="A database backup file is publicly accessible.",
                    evidence=f"HTTP {status} at {url}",
                    remediation="Remove backup files from the web root. Store backups securely.",
                    cvss_score=9.1,
                )

        # Admin panels — medium
        if any(admin in path for admin in ["/admin", "/wp-admin", "/cpanel", "/phpmyadmin"]):
            return Vulnerability(
                title="Admin Panel Discovered",
                severity="MEDIUM" if status in (401, 403) else "HIGH",
                url=url,
                description=f"An administration panel was found at {url}.",
                evidence=f"HTTP {status} at {url}",
                remediation=(
                    "Restrict admin panel access by IP, add multi-factor authentication, "
                    "and consider moving it to a non-standard URL."
                ),
                cvss_score=5.3 if status in (401, 403) else 8.8,
            )

        # Debug/info pages — medium
        if any(dbg in path for dbg in ["phpinfo", "debug", "server-status", "server-info"]):
            if status == 200:
                return Vulnerability(
                    title="Debug/Info Page Exposed",
                    severity="MEDIUM",
                    url=url,
                    description="A debug or server information page is publicly accessible.",
                    evidence=f"HTTP {status} at {url}",
                    remediation="Disable debug pages in production. Block access via server config.",
                    cvss_score=5.3,
                )

        # htaccess/htpasswd — high
        if ".htaccess" in path or ".htpasswd" in path:
            return Vulnerability(
                title="Server Configuration File Exposed",
                severity="HIGH",
                url=url,
                description=f"The file {path} is accessible, potentially revealing server configuration or credentials.",
                evidence=f"HTTP {status} at {url}",
                remediation="Block access to hidden files (starting with .) in server configuration.",
                cvss_score=7.5,
            )

        # GraphQL endpoint — info
        if "graphql" in path and status == 200:
            return Vulnerability(
                title="GraphQL Endpoint Discovered",
                severity="INFO",
                url=url,
                description="A GraphQL endpoint was discovered. Check for introspection and authorization.",
                evidence=f"HTTP {status} at {url}",
                remediation="Disable GraphQL introspection in production. Implement proper authorization.",
                cvss_score=2.0,
            )

        return None
