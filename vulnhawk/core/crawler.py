"""Async web crawler — discovers URLs, forms, and parameters on a target website."""

import asyncio
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup


@dataclass
class FormData:
    """Represents an HTML form discovered during crawling."""
    url: str  # Page the form was found on
    action: str  # Form action URL
    method: str  # GET or POST
    inputs: list[dict] = field(default_factory=list)  # Input fields


@dataclass
class CrawlResult:
    """Results from crawling a target website."""
    base_url: str
    urls: list[str] = field(default_factory=list)
    forms: list[FormData] = field(default_factory=list)
    parameters: dict[str, list[str]] = field(default_factory=dict)  # URL -> list of param names
    headers: dict[str, dict] = field(default_factory=dict)  # URL -> response headers
    cookies: dict[str, str] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)


async def crawl_target(
    target_url: str,
    max_depth: int = 2,
    max_concurrent: int = 10,
    timeout: float = 10.0,
    login_url: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> CrawlResult:
    """
    Crawl a target website and discover all pages, forms, and parameters.

    Args:
        target_url: Base URL to start crawling from
        max_depth: Maximum link-following depth
        max_concurrent: Maximum concurrent HTTP requests
        timeout: Request timeout in seconds
        login_url: Optional URL to POST login credentials to before crawling
        username: Username/email for authenticated scanning
        password: Password for authenticated scanning

    Returns:
        CrawlResult with all discovered URLs, forms, and parameters
    """
    result = CrawlResult(base_url=target_url)
    visited: set[str] = set()
    semaphore = asyncio.Semaphore(max_concurrent)

    parsed_base = urlparse(target_url)
    base_domain = parsed_base.netloc

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,  # Allow self-signed certs for testing
        headers={"User-Agent": "VulnHawk/1.0 Security Scanner"},
    ) as client:

        # ── Authenticated pre-crawl login ─────────────────────────────────────
        if login_url and username and password:
            try:
                # First GET the login page to grab any CSRF token
                login_page = await client.get(login_url)
                soup = BeautifulSoup(login_page.text, "lxml")
                form = soup.find("form")

                # Build login form data, injecting credentials
                login_data: dict[str, str] = {}
                if form:
                    for inp in form.find_all(["input", "select", "textarea"]):
                        name = inp.get("name", "")
                        val = inp.get("value", "")
                        if name:
                            login_data[name] = val

                # Detect username/password fields heuristically
                user_keys = {"username", "user", "email", "login", "name", "user_name"}
                pass_keys = {"password", "passwd", "pass", "pwd", "secret"}
                for key in list(login_data.keys()):
                    if key.lower() in user_keys:
                        login_data[key] = username
                    elif key.lower() in pass_keys:
                        login_data[key] = password

                # Fallback: inject by common names if not matched above
                if not any(k.lower() in user_keys for k in login_data):
                    login_data["username"] = username
                if not any(k.lower() in pass_keys for k in login_data):
                    login_data["password"] = password

                action = form.get("action", login_url) if form else login_url
                action = urljoin(login_url, action)
                await client.post(action, data=login_data)

                # Store session cookies into CrawlResult
                for name, value in client.cookies.items():
                    result.cookies[name] = value
            except Exception:
                pass  # Auth failure is non-fatal; scanning continues unauthenticated
        # ─────────────────────────────────────────────────────────────────────

        async def crawl_page(url: str, depth: int):
            """Crawl a single page and extract links, forms, params."""
            if depth > max_depth or url in visited:
                return

            # Normalize URL
            url = url.split("#")[0]  # Remove fragments
            if url in visited:
                return
            visited.add(url)

            async with semaphore:
                try:
                    response = await client.get(url)
                except (httpx.RequestError, httpx.HTTPStatusError):
                    return

            result.urls.append(url)
            result.headers[url] = dict(response.headers)

            # Store cookies
            for name, value in response.cookies.items():
                result.cookies[name] = value

            # Parse HTML
            if "text/html" not in response.headers.get("content-type", ""):
                return

            soup = BeautifulSoup(response.text, "lxml")

            # Detect technologies from headers and meta tags
            _detect_technologies(response, soup, result)

            # Extract forms
            for form in soup.find_all("form"):
                form_data = _extract_form(form, url)
                if form_data:
                    result.forms.append(form_data)

            # Extract URL parameters
            parsed = urlparse(url)
            if parsed.query:
                params = [p.split("=")[0] for p in parsed.query.split("&") if "=" in p]
                if params:
                    result.parameters[url] = params

            # Extract links for further crawling
            links = set()
            for tag in soup.find_all("a", href=True):
                href = tag["href"]
                full_url = urljoin(url, href)
                parsed_link = urlparse(full_url)

                # Only follow links on the same domain
                if parsed_link.netloc == base_domain:
                    links.add(full_url.split("#")[0])

            # Crawl discovered links
            tasks = [crawl_page(link, depth + 1) for link in links if link not in visited]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        # Start crawling from the target URL
        await crawl_page(target_url, 0)

    return result


def _extract_form(form_tag, page_url: str) -> FormData | None:
    """Extract form data from a BeautifulSoup form tag."""
    action = form_tag.get("action", "")
    if action:
        action = urljoin(page_url, action)
    else:
        action = page_url

    method = form_tag.get("method", "GET").upper()

    inputs = []
    for input_tag in form_tag.find_all(["input", "textarea", "select"]):
        input_data = {
            "name": input_tag.get("name", ""),
            "type": input_tag.get("type", "text"),
            "value": input_tag.get("value", ""),
        }
        if input_data["name"]:  # Only include named inputs
            inputs.append(input_data)

    if not inputs:
        return None

    return FormData(url=page_url, action=action, method=method, inputs=inputs)


def _detect_technologies(response: httpx.Response, soup: BeautifulSoup, result: CrawlResult):
    """Detect web technologies from response headers and HTML content."""
    headers = response.headers

    # Server header
    server = headers.get("server", "")
    if server and server not in result.technologies:
        result.technologies.append(f"Server: {server}")

    # X-Powered-By
    powered_by = headers.get("x-powered-by", "")
    if powered_by and powered_by not in result.technologies:
        result.technologies.append(f"Powered-By: {powered_by}")

    # Framework detection from meta tags
    generator = soup.find("meta", attrs={"name": "generator"})
    if generator and generator.get("content"):
        tech = f"Generator: {generator['content']}"
        if tech not in result.technologies:
            result.technologies.append(tech)
